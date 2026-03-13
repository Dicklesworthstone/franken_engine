//! Enrichment integration tests for `module_resolver`.
//!
//! Covers: Copy/Clone semantics, BTreeSet ordering, serde roundtrips, Debug
//! nonempty, Display coverage, JSON field-name stability, builder patterns,
//! resolver registration/resolution, policy hooks, host API surface,
//! error codes, std::error::Error trait.

use std::collections::BTreeSet;

use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::module_resolver::{
    AllowAllPolicy, CapabilityPolicyHook, DeterministicModuleResolver, HostApiErrorCode,
    HostApiPermissionDescriptor, HostApiRequest, ImportStyle, ModuleDefinition, ModuleDependency,
    ModulePolicyHook, ModuleProvenance, ModuleRecord, ModuleRequest, ModuleResolver,
    ModuleSourceKind, ModuleSyntax, RegistryError, RegistryErrorCode, ResolutionContext,
    ResolutionErrorCode, ResolutionEvent, ResolutionOutcome, ResolvedModule,
};

// -----------------------------------------------------------------------
// 1. Copy semantics for Copy types
// -----------------------------------------------------------------------

#[test]
fn enrichment_module_syntax_copy() {
    let a = ModuleSyntax::EsModule;
    let b = a;
    assert_eq!(a, b);
    let c = ModuleSyntax::CommonJs;
    let d = c;
    assert_eq!(c, d);
}

#[test]
fn enrichment_import_style_copy() {
    let a = ImportStyle::Import;
    let b = a;
    assert_eq!(a, b);
    let c = ImportStyle::Require;
    let d = c;
    assert_eq!(c, d);
}

#[test]
fn enrichment_module_source_kind_copy() {
    let a = ModuleSourceKind::BuiltIn;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_resolution_error_code_copy() {
    let a = ResolutionErrorCode::EmptySpecifier;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_host_api_error_code_copy() {
    let a = HostApiErrorCode::UnsupportedModule;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_registry_error_code_copy() {
    let a = RegistryErrorCode::EmptyKey;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_allow_all_policy_copy() {
    let a = AllowAllPolicy;
    let b = a;
    assert_eq!(a, b);
}

// -----------------------------------------------------------------------
// 2. Clone independence
// -----------------------------------------------------------------------

#[test]
fn enrichment_module_definition_clone_independence() {
    let a = ModuleDefinition::new(ModuleSyntax::EsModule, "export default 42;");
    let mut b = a.clone();
    b.source = "changed".to_string();
    assert_ne!(a.source, b.source);
}

#[test]
fn enrichment_module_dependency_clone_independence() {
    let a = ModuleDependency::new("lodash", ImportStyle::Import);
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_module_request_clone_independence() {
    let a = ModuleRequest::new("./foo", ImportStyle::Import);
    let mut b = a.clone();
    b.specifier = "changed".to_string();
    assert_ne!(a.specifier, b.specifier);
}

#[test]
fn enrichment_resolution_context_clone_independence() {
    let a = ResolutionContext::new("t", "d", "p");
    let mut b = a.clone();
    b.trace_id = "changed".to_string();
    assert_ne!(a.trace_id, b.trace_id);
}

#[test]
fn enrichment_capability_policy_hook_clone_independence() {
    let a = CapabilityPolicyHook::new(BTreeSet::new());
    let mut b = a.clone();
    b.granted_capabilities.insert(RuntimeCapability::PolicyRead);
    assert!(a.granted_capabilities.is_empty());
    assert_eq!(b.granted_capabilities.len(), 1);
}

// -----------------------------------------------------------------------
// 3. BTreeSet ordering
// -----------------------------------------------------------------------

#[test]
fn enrichment_module_syntax_btreeset() {
    let mut set = BTreeSet::new();
    set.insert(ModuleSyntax::EsModule);
    set.insert(ModuleSyntax::CommonJs);
    set.insert(ModuleSyntax::EsModule);
    assert_eq!(set.len(), 2);
}

#[test]
fn enrichment_import_style_btreeset() {
    let mut set = BTreeSet::new();
    set.insert(ImportStyle::Import);
    set.insert(ImportStyle::Require);
    set.insert(ImportStyle::Import);
    assert_eq!(set.len(), 2);
}

#[test]
fn enrichment_module_source_kind_btreeset() {
    let mut set = BTreeSet::new();
    set.insert(ModuleSourceKind::BuiltIn);
    set.insert(ModuleSourceKind::Workspace);
    set.insert(ModuleSourceKind::ExternalRegistry);
    set.insert(ModuleSourceKind::BuiltIn);
    assert_eq!(set.len(), 3);
}

// -----------------------------------------------------------------------
// 4. Serde roundtrips
// -----------------------------------------------------------------------

#[test]
fn enrichment_module_syntax_serde_roundtrip() {
    for v in [ModuleSyntax::EsModule, ModuleSyntax::CommonJs] {
        let json = serde_json::to_string(&v).unwrap();
        let back: ModuleSyntax = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

#[test]
fn enrichment_import_style_serde_roundtrip() {
    for v in [ImportStyle::Import, ImportStyle::Require] {
        let json = serde_json::to_string(&v).unwrap();
        let back: ImportStyle = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

#[test]
fn enrichment_module_source_kind_serde_roundtrip() {
    for v in [
        ModuleSourceKind::BuiltIn,
        ModuleSourceKind::Workspace,
        ModuleSourceKind::ExternalRegistry,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: ModuleSourceKind = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

#[test]
fn enrichment_module_dependency_serde_roundtrip() {
    let dep = ModuleDependency::new("lodash", ImportStyle::Require);
    let json = serde_json::to_string(&dep).unwrap();
    let back: ModuleDependency = serde_json::from_str(&json).unwrap();
    assert_eq!(dep, back);
}

#[test]
fn enrichment_module_definition_serde_roundtrip() {
    let def = ModuleDefinition::new(ModuleSyntax::EsModule, "export default 42;")
        .with_dependency(ModuleDependency::new("./bar", ImportStyle::Import))
        .require_capability(RuntimeCapability::PolicyRead)
        .with_provenance("test-origin");
    let json = serde_json::to_string(&def).unwrap();
    let back: ModuleDefinition = serde_json::from_str(&json).unwrap();
    assert_eq!(def, back);
}

#[test]
fn enrichment_module_provenance_serde_roundtrip() {
    let p = ModuleProvenance {
        kind: ModuleSourceKind::Workspace,
        origin: "src/lib.rs".to_string(),
    };
    let json = serde_json::to_string(&p).unwrap();
    let back: ModuleProvenance = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

#[test]
fn enrichment_module_request_serde_roundtrip() {
    let req = ModuleRequest::new("./foo", ImportStyle::Import).with_referrer("./bar");
    let json = serde_json::to_string(&req).unwrap();
    let back: ModuleRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req, back);
}

#[test]
fn enrichment_resolution_context_serde_roundtrip() {
    let ctx = ResolutionContext::new("t1", "d1", "p1");
    let json = serde_json::to_string(&ctx).unwrap();
    let back: ResolutionContext = serde_json::from_str(&json).unwrap();
    assert_eq!(ctx, back);
}

#[test]
fn enrichment_resolution_event_serde_roundtrip() {
    let ev = ResolutionEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "module_resolver".to_string(),
        event: "resolve".to_string(),
        outcome: "ok".to_string(),
        error_code: "".to_string(),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: ResolutionEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

#[test]
fn enrichment_resolution_error_code_serde_roundtrip() {
    for v in [
        ResolutionErrorCode::EmptySpecifier,
        ResolutionErrorCode::InvalidReferrer,
        ResolutionErrorCode::UnsupportedSpecifier,
        ResolutionErrorCode::ModuleNotFound,
        ResolutionErrorCode::PolicyDenied,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: ResolutionErrorCode = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

#[test]
fn enrichment_host_api_error_code_serde_roundtrip() {
    for v in [
        HostApiErrorCode::UnsupportedModule,
        HostApiErrorCode::UnsupportedOperation,
        HostApiErrorCode::PolicyDenied,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: HostApiErrorCode = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

#[test]
fn enrichment_host_api_request_serde_roundtrip() {
    let req = HostApiRequest::new("node:fs", "readFile");
    let json = serde_json::to_string(&req).unwrap();
    let back: HostApiRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req, back);
}

#[test]
fn enrichment_capability_policy_hook_serde_roundtrip() {
    let mut caps = BTreeSet::new();
    caps.insert(RuntimeCapability::PolicyRead);
    let hook = CapabilityPolicyHook::new(caps).deny_specifier("evil-module");
    let json = serde_json::to_string(&hook).unwrap();
    let back: CapabilityPolicyHook = serde_json::from_str(&json).unwrap();
    assert_eq!(hook, back);
}

#[test]
fn enrichment_registry_error_serde_roundtrip() {
    let re = RegistryError {
        code: RegistryErrorCode::EmptyKey,
        message: "test".to_string(),
    };
    let json = serde_json::to_string(&re).unwrap();
    let back: RegistryError = serde_json::from_str(&json).unwrap();
    assert_eq!(re, back);
}

// -----------------------------------------------------------------------
// 5. as_str / stable_code coverage
// -----------------------------------------------------------------------

#[test]
fn enrichment_module_syntax_as_str() {
    assert_eq!(ModuleSyntax::EsModule.as_str(), "esm");
    assert_eq!(ModuleSyntax::CommonJs.as_str(), "cjs");
}

#[test]
fn enrichment_import_style_as_str() {
    assert_eq!(ImportStyle::Import.as_str(), "import");
    assert_eq!(ImportStyle::Require.as_str(), "require");
}

#[test]
fn enrichment_module_source_kind_as_str() {
    assert_eq!(ModuleSourceKind::BuiltIn.as_str(), "builtin");
    assert_eq!(ModuleSourceKind::Workspace.as_str(), "workspace");
    assert_eq!(
        ModuleSourceKind::ExternalRegistry.as_str(),
        "external_registry"
    );
}

#[test]
fn enrichment_resolution_error_code_stable_codes() {
    assert_eq!(
        ResolutionErrorCode::EmptySpecifier.stable_code(),
        "FE-MODRES-0001"
    );
    assert_eq!(
        ResolutionErrorCode::InvalidReferrer.stable_code(),
        "FE-MODRES-0002"
    );
    assert_eq!(
        ResolutionErrorCode::UnsupportedSpecifier.stable_code(),
        "FE-MODRES-0003"
    );
    assert_eq!(
        ResolutionErrorCode::ModuleNotFound.stable_code(),
        "FE-MODRES-0004"
    );
    assert_eq!(
        ResolutionErrorCode::PolicyDenied.stable_code(),
        "FE-MODRES-0005"
    );
}

#[test]
fn enrichment_host_api_error_code_stable_codes() {
    assert_eq!(
        HostApiErrorCode::UnsupportedModule.stable_code(),
        "FE-HOSTAPI-0001"
    );
    assert_eq!(
        HostApiErrorCode::UnsupportedOperation.stable_code(),
        "FE-HOSTAPI-0002"
    );
    assert_eq!(
        HostApiErrorCode::PolicyDenied.stable_code(),
        "FE-HOSTAPI-0003"
    );
}

// -----------------------------------------------------------------------
// 6. Debug nonempty
// -----------------------------------------------------------------------

#[test]
fn enrichment_module_syntax_debug() {
    assert!(!format!("{:?}", ModuleSyntax::EsModule).is_empty());
}

#[test]
fn enrichment_import_style_debug() {
    assert!(!format!("{:?}", ImportStyle::Import).is_empty());
}

#[test]
fn enrichment_module_source_kind_debug() {
    assert!(!format!("{:?}", ModuleSourceKind::BuiltIn).is_empty());
}

#[test]
fn enrichment_module_definition_debug() {
    let def = ModuleDefinition::new(ModuleSyntax::EsModule, "x");
    assert!(!format!("{def:?}").is_empty());
}

#[test]
fn enrichment_module_dependency_debug() {
    let dep = ModuleDependency::new("foo", ImportStyle::Import);
    assert!(!format!("{dep:?}").is_empty());
}

#[test]
fn enrichment_module_request_debug() {
    let req = ModuleRequest::new("./m", ImportStyle::Import);
    assert!(!format!("{req:?}").is_empty());
}

#[test]
fn enrichment_resolution_context_debug() {
    let ctx = ResolutionContext::new("t", "d", "p");
    assert!(!format!("{ctx:?}").is_empty());
}

#[test]
fn enrichment_resolution_error_code_debug() {
    assert!(!format!("{:?}", ResolutionErrorCode::EmptySpecifier).is_empty());
}

#[test]
fn enrichment_host_api_error_code_debug() {
    assert!(!format!("{:?}", HostApiErrorCode::UnsupportedModule).is_empty());
}

#[test]
fn enrichment_registry_error_debug() {
    let re = RegistryError {
        code: RegistryErrorCode::EmptyKey,
        message: "x".to_string(),
    };
    assert!(!format!("{re:?}").is_empty());
}

#[test]
fn enrichment_capability_policy_hook_debug() {
    let hook = CapabilityPolicyHook::new(BTreeSet::new());
    assert!(!format!("{hook:?}").is_empty());
}

// -----------------------------------------------------------------------
// 7. Display coverage / std::error::Error
// -----------------------------------------------------------------------

#[test]
fn enrichment_registry_error_display_nonempty() {
    let re = RegistryError {
        code: RegistryErrorCode::EmptyKey,
        message: "bad key".to_string(),
    };
    let s = format!("{re}");
    assert!(!s.is_empty());
    assert!(s.contains("bad key"));
}

#[test]
fn enrichment_registry_error_implements_std_error() {
    let re = RegistryError {
        code: RegistryErrorCode::EmptyKey,
        message: "test".to_string(),
    };
    let boxed: Box<dyn std::error::Error> = Box::new(re);
    assert!(!boxed.to_string().is_empty());
}

// -----------------------------------------------------------------------
// 8. Builder patterns
// -----------------------------------------------------------------------

#[test]
fn enrichment_module_definition_builder() {
    let def = ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = {};")
        .with_dependency(ModuleDependency::new("path", ImportStyle::Require))
        .with_dependency(ModuleDependency::new("fs", ImportStyle::Require))
        .require_capability(RuntimeCapability::PolicyRead)
        .require_capability(RuntimeCapability::PolicyWrite)
        .with_provenance("test-pkg");
    assert_eq!(def.syntax, ModuleSyntax::CommonJs);
    assert_eq!(def.dependencies.len(), 2);
    assert_eq!(def.required_capabilities.len(), 2);
    assert_eq!(def.provenance_origin, "test-pkg");
}

#[test]
fn enrichment_module_request_builder() {
    let req = ModuleRequest::new("lodash", ImportStyle::Import).with_referrer("./app.js");
    assert_eq!(req.specifier, "lodash");
    assert_eq!(req.referrer.as_deref(), Some("./app.js"));
    assert_eq!(req.style, ImportStyle::Import);
}

#[test]
fn enrichment_capability_policy_hook_builder() {
    let mut caps = BTreeSet::new();
    caps.insert(RuntimeCapability::NetworkEgress);
    let hook = CapabilityPolicyHook::new(caps)
        .deny_specifier("banned-module")
        .deny_host_api_descriptor("desc-1");
    assert!(
        hook.granted_capabilities
            .contains(&RuntimeCapability::NetworkEgress)
    );
    assert!(hook.denied_specifiers.contains("banned-module"));
    assert!(hook.denied_host_api_descriptors.contains("desc-1"));
}

// -----------------------------------------------------------------------
// 9. DeterministicModuleResolver registration
// -----------------------------------------------------------------------

#[test]
fn enrichment_resolver_new_and_root_dir() {
    let resolver = DeterministicModuleResolver::new("/app");
    assert_eq!(resolver.root_dir(), "/app");
}

#[test]
fn enrichment_resolver_register_builtin() {
    let mut resolver = DeterministicModuleResolver::new("/app");
    let def = ModuleDefinition::new(ModuleSyntax::EsModule, "export const x = 1;");
    let result = resolver.register_builtin("node:path", def);
    assert!(result.is_ok());
}

#[test]
fn enrichment_resolver_register_builtin_empty_key_error() {
    let mut resolver = DeterministicModuleResolver::new("/app");
    let def = ModuleDefinition::new(ModuleSyntax::EsModule, "x");
    let result = resolver.register_builtin("", def);
    assert!(result.is_err());
}

#[test]
fn enrichment_resolver_register_workspace_module() {
    let mut resolver = DeterministicModuleResolver::new("/app");
    let def = ModuleDefinition::new(ModuleSyntax::EsModule, "export default {};");
    let result = resolver.register_workspace_module("./lib/utils", def);
    assert!(result.is_ok());
}

#[test]
fn enrichment_resolver_register_workspace_module_empty_key_error() {
    let mut resolver = DeterministicModuleResolver::new("/app");
    let def = ModuleDefinition::new(ModuleSyntax::EsModule, "x");
    let result = resolver.register_workspace_module("", def);
    assert!(result.is_err());
}

#[test]
fn enrichment_resolver_register_external_module() {
    let mut resolver = DeterministicModuleResolver::new("/app");
    let def = ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = {};");
    let result = resolver.register_external_module("lodash", def);
    assert!(result.is_ok());
}

// -----------------------------------------------------------------------
// 10. Resolution with AllowAllPolicy
// -----------------------------------------------------------------------

#[test]
fn enrichment_resolve_builtin_with_allow_all() {
    let mut resolver = DeterministicModuleResolver::new("/app");
    let def = ModuleDefinition::new(ModuleSyntax::EsModule, "export const sep = '/';");
    resolver.register_builtin("node:path", def).unwrap();

    let req = ModuleRequest::new("node:path", ImportStyle::Import);
    let ctx = ResolutionContext::new("t", "d", "p");
    let policy = AllowAllPolicy;
    let result = resolver.resolve(&req, &ctx, &policy);
    assert!(result.is_ok());
    let outcome = result.unwrap();
    assert_eq!(outcome.module.request_specifier, "node:path");
}

#[test]
fn enrichment_resolve_workspace_with_allow_all() {
    let mut resolver = DeterministicModuleResolver::new("/app");
    let def = ModuleDefinition::new(ModuleSyntax::EsModule, "export const util = true;");
    resolver
        .register_workspace_module("./lib/util", def)
        .unwrap();

    // Workspace module registered as "./lib/util" normalizes to "/app/lib/util".
    // Resolve using the absolute path (relative specifiers require a referrer).
    let req = ModuleRequest::new("/app/lib/util", ImportStyle::Import);
    let ctx = ResolutionContext::new("t", "d", "p");
    let policy = AllowAllPolicy;
    let result = resolver.resolve(&req, &ctx, &policy);
    assert!(result.is_ok());
    let outcome = result.unwrap();
    assert_eq!(outcome.module.canonical_specifier, "/app/lib/util");
}

#[test]
fn enrichment_resolve_not_found() {
    let resolver = DeterministicModuleResolver::new("/app");
    let req = ModuleRequest::new("nonexistent", ImportStyle::Import);
    let ctx = ResolutionContext::new("t", "d", "p");
    let policy = AllowAllPolicy;
    let result = resolver.resolve(&req, &ctx, &policy);
    assert!(result.is_err());
}

#[test]
fn enrichment_resolve_empty_specifier_error() {
    let resolver = DeterministicModuleResolver::new("/app");
    let req = ModuleRequest::new("", ImportStyle::Import);
    let ctx = ResolutionContext::new("t", "d", "p");
    let policy = AllowAllPolicy;
    let result = resolver.resolve(&req, &ctx, &policy);
    assert!(result.is_err());
}

// -----------------------------------------------------------------------
// 11. CapabilityPolicyHook denials
// -----------------------------------------------------------------------

#[test]
fn enrichment_capability_policy_denies_missing_capability() {
    let mut resolver = DeterministicModuleResolver::new("/app");
    let def = ModuleDefinition::new(ModuleSyntax::EsModule, "export const f = 1;")
        .require_capability(RuntimeCapability::PolicyRead);
    resolver.register_builtin("node:fs", def).unwrap();

    let req = ModuleRequest::new("node:fs", ImportStyle::Import);
    let ctx = ResolutionContext::new("t", "d", "p");
    // Policy has no capabilities -> should deny
    let policy = CapabilityPolicyHook::new(BTreeSet::new());
    let result = resolver.resolve(&req, &ctx, &policy);
    assert!(result.is_err());
}

#[test]
fn enrichment_capability_policy_allows_with_capability() {
    let mut resolver = DeterministicModuleResolver::new("/app");
    let def = ModuleDefinition::new(ModuleSyntax::EsModule, "export const f = 1;")
        .require_capability(RuntimeCapability::PolicyRead);
    resolver.register_builtin("node:fs", def).unwrap();

    let req = ModuleRequest::new("node:fs", ImportStyle::Import);
    let ctx = ResolutionContext::new("t", "d", "p");
    let mut caps = BTreeSet::new();
    caps.insert(RuntimeCapability::PolicyRead);
    let policy = CapabilityPolicyHook::new(caps);
    let result = resolver.resolve(&req, &ctx, &policy);
    assert!(result.is_ok());
}

#[test]
fn enrichment_capability_policy_denies_specifier() {
    let mut resolver = DeterministicModuleResolver::new("/app");
    let def = ModuleDefinition::new(ModuleSyntax::EsModule, "export const x = 1;");
    resolver.register_builtin("banned", def).unwrap();

    let req = ModuleRequest::new("banned", ImportStyle::Import);
    let ctx = ResolutionContext::new("t", "d", "p");
    let policy = CapabilityPolicyHook::new(BTreeSet::new()).deny_specifier("banned");
    let result = resolver.resolve(&req, &ctx, &policy);
    assert!(result.is_err());
}

// -----------------------------------------------------------------------
// 12. ModuleRecord canonical hash
// -----------------------------------------------------------------------

#[test]
fn enrichment_module_record_canonical_hash_deterministic() {
    let rec = ModuleRecord {
        id: "mod1".to_string(),
        syntax: ModuleSyntax::EsModule,
        source: "export default 42;".to_string(),
        dependencies: vec![],
        required_capabilities: BTreeSet::new(),
        provenance: ModuleProvenance {
            kind: ModuleSourceKind::BuiltIn,
            origin: "test".to_string(),
        },
    };
    let h1 = rec.canonical_hash();
    let h2 = rec.canonical_hash();
    assert_eq!(h1, h2);
}

#[test]
fn enrichment_module_record_canonical_bytes_nonempty() {
    let rec = ModuleRecord {
        id: "mod1".to_string(),
        syntax: ModuleSyntax::CommonJs,
        source: "module.exports = {};".to_string(),
        dependencies: vec![ModuleDependency::new("path", ImportStyle::Require)],
        required_capabilities: BTreeSet::new(),
        provenance: ModuleProvenance {
            kind: ModuleSourceKind::Workspace,
            origin: "src".to_string(),
        },
    };
    assert!(!rec.canonical_bytes().is_empty());
}

// -----------------------------------------------------------------------
// 13. JSON field-name stability
// -----------------------------------------------------------------------

#[test]
fn enrichment_module_definition_json_fields() {
    let def = ModuleDefinition::new(ModuleSyntax::EsModule, "x").with_provenance("origin");
    let json = serde_json::to_string(&def).unwrap();
    for field in [
        "syntax",
        "source",
        "dependencies",
        "required_capabilities",
        "provenance_origin",
    ] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

#[test]
fn enrichment_module_request_json_fields() {
    let req = ModuleRequest::new("./foo", ImportStyle::Import).with_referrer("./bar");
    let json = serde_json::to_string(&req).unwrap();
    for field in ["specifier", "referrer", "style"] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

#[test]
fn enrichment_resolution_context_json_fields() {
    let ctx = ResolutionContext::new("t", "d", "p");
    let json = serde_json::to_string(&ctx).unwrap();
    for field in ["trace_id", "decision_id", "policy_id"] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

#[test]
fn enrichment_host_api_request_json_fields() {
    let req = HostApiRequest::new("node:fs", "readFile");
    let json = serde_json::to_string(&req).unwrap();
    for field in ["module_specifier", "operation"] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

#[test]
fn enrichment_host_api_permission_descriptor_json_fields() {
    let desc = HostApiPermissionDescriptor {
        descriptor_id: "d1".to_string(),
        module_specifier: "node:fs".to_string(),
        operation: "readFile".to_string(),
        required_capabilities: {
            let mut s = BTreeSet::new();
            s.insert(RuntimeCapability::PolicyRead);
            s
        },
        remediation: "Grant fs_read".to_string(),
    };
    let json = serde_json::to_string(&desc).unwrap();
    for field in [
        "descriptor_id",
        "module_specifier",
        "operation",
        "required_capabilities",
        "remediation",
    ] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

#[test]
fn enrichment_capability_policy_hook_json_fields() {
    let hook = CapabilityPolicyHook::new(BTreeSet::new()).deny_specifier("bad");
    let json = serde_json::to_string(&hook).unwrap();
    for field in [
        "granted_capabilities",
        "denied_specifiers",
        "denied_host_api_descriptors",
    ] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

// -----------------------------------------------------------------------
// 14. AllowAllPolicy trait implementation
// -----------------------------------------------------------------------

#[test]
fn enrichment_allow_all_policy_always_ok() {
    let policy = AllowAllPolicy;
    let rec = ModuleRecord {
        id: "mod".to_string(),
        syntax: ModuleSyntax::EsModule,
        source: "x".to_string(),
        dependencies: vec![],
        required_capabilities: {
            let mut s = BTreeSet::new();
            s.insert(RuntimeCapability::NetworkEgress);
            s
        },
        provenance: ModuleProvenance {
            kind: ModuleSourceKind::BuiltIn,
            origin: "test".to_string(),
        },
    };
    let req = ModuleRequest::new("test", ImportStyle::Import);
    let ctx = ResolutionContext::new("t", "d", "p");
    assert!(policy.authorize(&req, &rec, &ctx).is_ok());
}

// -----------------------------------------------------------------------
// 15. Resolution outcome serde roundtrip
// -----------------------------------------------------------------------

#[test]
fn enrichment_resolved_module_serde_roundtrip() {
    let rm = ResolvedModule {
        request_specifier: "./foo".to_string(),
        canonical_specifier: "/app/foo.js".to_string(),
        record: ModuleRecord {
            id: "mod1".to_string(),
            syntax: ModuleSyntax::EsModule,
            source: "export default 42;".to_string(),
            dependencies: vec![],
            required_capabilities: BTreeSet::new(),
            provenance: ModuleProvenance {
                kind: ModuleSourceKind::Workspace,
                origin: "src".to_string(),
            },
        },
        content_hash: ContentHash::compute(b"test"),
        probe_sequence: vec!["./foo.js".to_string(), "./foo/index.js".to_string()],
    };
    let json = serde_json::to_string(&rm).unwrap();
    let back: ResolvedModule = serde_json::from_str(&json).unwrap();
    assert_eq!(rm, back);
}

#[test]
fn enrichment_resolution_outcome_serde_roundtrip() {
    let ro = ResolutionOutcome {
        module: ResolvedModule {
            request_specifier: "test".to_string(),
            canonical_specifier: "test".to_string(),
            record: ModuleRecord {
                id: "m".to_string(),
                syntax: ModuleSyntax::CommonJs,
                source: "s".to_string(),
                dependencies: vec![],
                required_capabilities: BTreeSet::new(),
                provenance: ModuleProvenance {
                    kind: ModuleSourceKind::BuiltIn,
                    origin: "o".to_string(),
                },
            },
            content_hash: ContentHash::compute(b"t"),
            probe_sequence: vec![],
        },
        event: ResolutionEvent {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "c".to_string(),
            event: "e".to_string(),
            outcome: "ok".to_string(),
            error_code: "".to_string(),
        },
    };
    let json = serde_json::to_string(&ro).unwrap();
    let back: ResolutionOutcome = serde_json::from_str(&json).unwrap();
    assert_eq!(ro, back);
}
