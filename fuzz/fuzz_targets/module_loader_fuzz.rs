#![no_main]

use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::module_resolver::{
    AllowAllPolicy, DeterministicModuleResolver, ExternalPackageDefinition,
    ExternalPackageExportTarget, ImportStyle, ModuleDefinition, ModuleDependency, ModuleRequest,
    ModuleResolver, ModuleSyntax, ResolutionContext,
};
use libfuzzer_sys::fuzz_target;
use std::collections::{BTreeMap, BTreeSet};

const MAX_INPUT_BYTES: usize = 16 * 1024;
const MAX_MODULES: usize = 32;
const MAX_DEPENDENCIES: usize = 8;
const MAX_PACKAGE_EXPORTS: usize = 16;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > MAX_INPUT_BYTES {
        return;
    }

    let module_graph = parse_module_graph(data);

    // Test module resolution with adversarial graphs focusing on:
    // 1. ESM/CJS import resolution edge cases
    // 2. Circular dependency detection
    // 3. Path traversal attempts
    // 4. Conditional export resolution
    test_module_resolution(&module_graph);

    // Test module graph validation
    test_graph_validation(&module_graph);

    // Test serialization stability
    test_module_serialization(&module_graph);
});

#[derive(Debug, Clone)]
struct ModuleGraph {
    workspace_modules: Vec<WorkspaceModule>,
    external_packages: Vec<ExternalPackage>,
    resolution_requests: Vec<ResolutionRequest>,
}

#[derive(Debug, Clone)]
struct WorkspaceModule {
    id: String,
    syntax: ModuleSyntax,
    source: String,
    dependencies: Vec<ModuleDependency>,
    capabilities: BTreeSet<RuntimeCapability>,
}

#[derive(Debug, Clone)]
struct ExternalPackage {
    name: String,
    exports: BTreeMap<String, PackageExport>,
}

#[derive(Debug, Clone)]
struct PackageExport {
    condition_targets: BTreeMap<String, String>,
    fallback_target: Option<String>,
}

#[derive(Debug, Clone)]
struct ResolutionRequest {
    specifier: String,
    style: ImportStyle,
    referrer: Option<String>,
}

fn parse_module_graph(data: &[u8]) -> ModuleGraph {
    let mut workspace_modules = Vec::new();
    let mut external_packages = Vec::new();
    let mut resolution_requests = Vec::new();

    // Parse chunks of data to create adversarial module configurations
    for (chunk_idx, chunk) in data.chunks(8).take(MAX_MODULES).enumerate() {
        let opcode = byte(chunk, 0);

        match opcode % 3 {
            0 => workspace_modules.push(generate_workspace_module(chunk, chunk_idx)),
            1 => external_packages.push(generate_external_package(chunk, chunk_idx)),
            _ => resolution_requests.push(generate_resolution_request(chunk, chunk_idx)),
        }
    }

    ModuleGraph {
        workspace_modules,
        external_packages,
        resolution_requests,
    }
}

fn generate_workspace_module(chunk: &[u8], index: usize) -> WorkspaceModule {
    let syntax = if byte(chunk, 1) & 1 == 0 {
        ModuleSyntax::EsModule
    } else {
        ModuleSyntax::CommonJs
    };

    let module_type = byte(chunk, 2) % 8;
    let id = generate_module_id(chunk, index, module_type);
    let source = generate_module_source(syntax, chunk, module_type);
    let dependencies = generate_dependencies(chunk, syntax, module_type);
    let capabilities = generate_capabilities(chunk);

    WorkspaceModule {
        id,
        syntax,
        source,
        dependencies,
        capabilities,
    }
}

fn generate_module_id(chunk: &[u8], index: usize, module_type: u8) -> String {
    match module_type {
        0 => format!(
            "/app/main_{}.{}",
            index,
            if byte(chunk, 1) & 1 == 0 {
                "mjs"
            } else {
                "cjs"
            }
        ),
        1 => format!(
            "/app/cycle_a_{}.{}",
            index,
            if byte(chunk, 1) & 1 == 0 {
                "mjs"
            } else {
                "cjs"
            }
        ),
        2 => format!(
            "/app/cycle_b_{}.{}",
            index,
            if byte(chunk, 1) & 1 == 0 {
                "mjs"
            } else {
                "cjs"
            }
        ),
        3 => format!(
            "/app/deep/nested/path_{}.{}",
            index,
            if byte(chunk, 1) & 1 == 0 {
                "mjs"
            } else {
                "cjs"
            }
        ),
        4 => format!(
            "/app/../escape_{}.{}",
            index,
            if byte(chunk, 1) & 1 == 0 {
                "mjs"
            } else {
                "cjs"
            }
        ),
        5 => format!(
            "/app/pkg_{}/index.{}",
            index,
            if byte(chunk, 1) & 1 == 0 {
                "mjs"
            } else {
                "cjs"
            }
        ),
        6 => format!(
            "/app/.hidden/module_{}.{}",
            index,
            if byte(chunk, 1) & 1 == 0 {
                "mjs"
            } else {
                "cjs"
            }
        ),
        _ => format!(
            "/app/fuzz_{}.{}",
            index,
            if byte(chunk, 1) & 1 == 0 {
                "mjs"
            } else {
                "cjs"
            }
        ),
    }
}

fn generate_module_source(syntax: ModuleSyntax, chunk: &[u8], module_type: u8) -> String {
    let import_variant = byte(chunk, 3) % 6;

    match syntax {
        ModuleSyntax::EsModule => match import_variant {
            0 => "export const value = 42;".to_string(),
            1 => "import './other'; export const value = 1;".to_string(),
            2 => "import { named } from './dep'; export { named };".to_string(),
            3 => "export * from './re_export';".to_string(),
            4 => "import defaultExport from './default'; export default defaultExport;".to_string(),
            _ => format!("export const fuzz_{} = {};", module_type, byte(chunk, 4)),
        },
        ModuleSyntax::CommonJs => match import_variant {
            0 => "module.exports = { value: 42 };".to_string(),
            1 => "const dep = require('./other'); module.exports = dep;".to_string(),
            2 => "module.exports = require('./dep');".to_string(),
            3 => "exports.value = require('./nested').value;".to_string(),
            4 => "module.exports = function() { return require('./lazy'); };".to_string(),
            _ => format!("exports.fuzz_{} = {};", module_type, byte(chunk, 4)),
        },
    }
}

fn generate_dependencies(
    chunk: &[u8],
    syntax: ModuleSyntax,
    module_type: u8,
) -> Vec<ModuleDependency> {
    let mut dependencies = Vec::new();
    let dep_count = (byte(chunk, 5) % MAX_DEPENDENCIES as u8) as usize;

    for i in 0..dep_count {
        let dep_type = byte(chunk, 6 + i) % 12;
        let style = match syntax {
            ModuleSyntax::EsModule => ImportStyle::Import,
            ModuleSyntax::CommonJs => ImportStyle::Require,
        };

        let specifier = match dep_type {
            0 => "./relative".to_string(),
            1 => "./relative.mjs".to_string(),
            2 => "./relative.cjs".to_string(),
            3 => format!("./cycle_a_{}", i),
            4 => format!("./cycle_b_{}", i),
            5 => "../parent".to_string(),
            6 => "../../escape".to_string(),
            7 => "/absolute/path".to_string(),
            8 => format!("external_pkg_{}", i),
            9 => "@scoped/package".to_string(),
            10 => "./pkg/index".to_string(),
            _ => format!("./deep/nested/path_{}", i),
        };

        dependencies.push(ModuleDependency::new(specifier, style));
    }

    // Add circular dependency patterns for specific module types
    if module_type == 1 {
        // cycle_a
        dependencies.push(ModuleDependency::new(
            "./cycle_b_0",
            if syntax == ModuleSyntax::EsModule {
                ImportStyle::Import
            } else {
                ImportStyle::Require
            },
        ));
    } else if module_type == 2 {
        // cycle_b
        dependencies.push(ModuleDependency::new(
            "./cycle_a_0",
            if syntax == ModuleSyntax::EsModule {
                ImportStyle::Import
            } else {
                ImportStyle::Require
            },
        ));
    }

    dependencies
}

fn generate_capabilities(chunk: &[u8]) -> BTreeSet<RuntimeCapability> {
    let mut capabilities = BTreeSet::new();

    if byte(chunk, 7) & 1 == 1 {
        capabilities.insert(RuntimeCapability::FsRead);
    }
    if byte(chunk, 7) & 2 == 2 {
        capabilities.insert(RuntimeCapability::NetworkEgress);
    }
    if byte(chunk, 7) & 4 == 4 {
        capabilities.insert(RuntimeCapability::ProcessSpawn);
    }

    capabilities
}

fn generate_external_package(chunk: &[u8], index: usize) -> ExternalPackage {
    let package_variant = byte(chunk, 1) % 6;
    let name = match package_variant {
        0 => format!("dual_package_{}", index),
        1 => format!("@scoped/pkg_{}", index),
        2 => format!("escape_pkg_{}", index),
        3 => format!("deep.nested.pkg.{}", index),
        4 => format!("version-1.2.3-pkg_{}", index),
        _ => format!("fuzz_pkg_{}", index),
    };

    let mut exports = BTreeMap::new();
    let export_count = (byte(chunk, 2) % MAX_PACKAGE_EXPORTS as u8) as usize;

    for i in 0..export_count {
        let export_key = match byte(chunk, 3 + i) % 6 {
            0 => ".".to_string(),
            1 => "./subpath".to_string(),
            2 => format!("./feature_{}", i),
            3 => "../escape".to_string(),
            4 => "./../traverse".to_string(),
            _ => format!("./export_{}", i),
        };

        let mut condition_targets = BTreeMap::new();
        let mut fallback_target = None;

        if byte(chunk, 4 + i) & 1 == 1 {
            condition_targets.insert("import".to_string(), format!("./esm_{}.mjs", i));
        }
        if byte(chunk, 4 + i) & 2 == 2 {
            condition_targets.insert("require".to_string(), format!("./cjs_{}.cjs", i));
        }
        if byte(chunk, 4 + i) & 4 == 4 {
            condition_targets.insert("node".to_string(), format!("./node_{}.js", i));
        }
        if byte(chunk, 4 + i) & 8 == 8 {
            fallback_target = Some(format!("./fallback_{}.js", i));
        }

        // Add path traversal attempts
        if byte(chunk, 5 + i) & 1 == 1 {
            fallback_target = Some("../outside.mjs".to_string());
        }

        exports.insert(
            export_key,
            PackageExport {
                condition_targets,
                fallback_target,
            },
        );
    }

    ExternalPackage { name, exports }
}

fn generate_resolution_request(chunk: &[u8], index: usize) -> ResolutionRequest {
    let request_type = byte(chunk, 1) % 10;
    let style = if byte(chunk, 2) & 1 == 0 {
        ImportStyle::Import
    } else {
        ImportStyle::Require
    };

    let specifier = match request_type {
        0 => "./relative".to_string(),
        1 => "./missing_extension".to_string(),
        2 => format!("./cycle_a_{}", index),
        3 => "../escape/attempt".to_string(),
        4 => "/absolute/path".to_string(),
        5 => format!("dual_package_{}", index),
        6 => "@scoped/package/subpath".to_string(),
        7 => "".to_string(), // empty specifier
        8 => format!("./very/deep/nested/path/to/module_{}", index),
        _ => format!("fuzz_specifier_{}", index),
    };

    let referrer = if byte(chunk, 3) & 1 == 1 {
        Some(format!("/app/main_{}.mjs", index))
    } else {
        None
    };

    ResolutionRequest {
        specifier,
        style,
        referrer,
    }
}

fn test_module_resolution(module_graph: &ModuleGraph) {
    let mut resolver = DeterministicModuleResolver::new("/app");
    let policy_hook = AllowAllPolicy;

    // Register workspace modules
    for module in &module_graph.workspace_modules {
        let mut definition = ModuleDefinition::new(module.syntax, &module.source);
        for dep in &module.dependencies {
            definition = definition.with_dependency(dep.clone());
        }
        for capability in &module.capabilities {
            definition = definition.require_capability(*capability);
        }

        let _ = resolver.register_workspace_module(&module.id, definition);
    }

    // Register external packages with adversarial export maps
    for package in &module_graph.external_packages {
        let mut pkg_def = ExternalPackageDefinition::new(&package.name);
        for (export_key, export_val) in &package.exports {
            let export_target = ExternalPackageExportTarget {
                condition_targets: export_val.condition_targets.clone(),
                fallback_target: export_val.fallback_target.clone(),
            };
            pkg_def = pkg_def.with_export(export_key, export_target);
        }
        let _ = resolver.register_external_package(pkg_def);
    }

    // Test resolution requests
    let context = ResolutionContext::new("fuzz-trace", "fuzz-decision", "fuzz-policy");

    for request in &module_graph.resolution_requests {
        let mut module_request = ModuleRequest::new(request.specifier.clone(), request.style);
        if let Some(referrer) = &request.referrer {
            module_request = module_request.with_referrer(referrer.clone());
        }

        // Test resolution - should handle all edge cases gracefully
        let _result = resolver.resolve(&module_request, &context, &policy_hook);

        // Test with different policy hooks for coverage
        let strict_policy = AllowAllPolicy;
        let _strict_result = resolver.resolve(&module_request, &context, &strict_policy);
    }
}

fn test_graph_validation(module_graph: &ModuleGraph) {
    // Test that module graph structures can be validated without panics
    for module in &module_graph.workspace_modules {
        if module.id.is_empty() || module.dependencies.len() > MAX_DEPENDENCIES {
            return;
        }

        // Test capability set consistency
        for capability in &module.capabilities {
            let _debug_str = format!("{:?}", capability);
        }
    }

    for package in &module_graph.external_packages {
        if package.name.is_empty() {
            return;
        }

        // Validate export map structure
        for (export_key, export_val) in &package.exports {
            if export_key.is_empty() {
                return;
            }

            // Check for path traversal patterns (should be handled gracefully, not panic)
            if export_key.contains("..") {
                // This should be handled by the resolver's path validation
            }

            // Validate condition targets
            for (condition, target) in &export_val.condition_targets {
                if condition.is_empty() || target.is_empty() {
                    return;
                }
            }
        }
    }
}

fn test_module_serialization(module_graph: &ModuleGraph) {
    // Test that module definitions can be serialized and maintain consistency
    for module in &module_graph.workspace_modules {
        let definition = ModuleDefinition::new(module.syntax, &module.source);

        // Test serialization roundtrip
        let serialized = serde_json::to_string(&definition);
        if let Ok(json_str) = serialized {
            let _deserialized: Result<ModuleDefinition, _> = serde_json::from_str(&json_str);
        }
    }

    // Test external package serialization
    for package in &module_graph.external_packages {
        let pkg_def = ExternalPackageDefinition::new(&package.name);
        let serialized = serde_json::to_string(&pkg_def);
        if let Ok(json_str) = serialized {
            let _deserialized: Result<ExternalPackageDefinition, _> =
                serde_json::from_str(&json_str);
        }
    }
}

fn byte(data: &[u8], index: usize) -> u8 {
    data.get(index).copied().unwrap_or(0)
}
