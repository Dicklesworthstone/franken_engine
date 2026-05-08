#![no_main]

use std::collections::{BTreeMap, BTreeSet};
use frankenengine_engine::ts_module_resolution::{
    DeterministicTsModuleResolver, TsModuleRequest, TsResolutionContext,
    TsModuleResolutionConfig, TsRequestStyle, TsModuleResolutionMode,
    TsPackageDefinition, TsPackageExportTarget
};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    // Guard against extremely large inputs that would slow down fuzzing
    if data.is_empty() || data.len() > MAX_INPUT_BYTES {
        return;
    }

    // Extract components from fuzzer input
    let config = fuzz_config(data);
    let files = fuzz_files(data);
    let packages = fuzz_packages(data);
    let request = fuzz_request(data);
    let context = fuzz_context(data);

    // Create resolver with fuzzed configuration
    let mut resolver = DeterministicTsModuleResolver::new(config);

    // Register fuzzed files
    for file in files {
        resolver.register_file(&file);
    }

    // Register fuzzed packages
    for (_, package) in packages {
        resolver.register_package(package);
    }

    // Test the target function - should not panic on any input
    let result = resolver.resolve(&request, &context);

    match result {
        Ok(outcome) => {
            // Validate invariants for successful resolution:
            // 1. resolved_path should be non-empty
            assert!(!outcome.resolved_path.is_empty(),
                   "Resolved path should not be empty");

            // 2. resolved_path should be an absolute path (starts with /)
            assert!(outcome.resolved_path.starts_with('/'),
                   "Resolved path should be absolute: {}", outcome.resolved_path);

            // 3. request_specifier should match input
            assert_eq!(outcome.request_specifier, request.specifier,
                      "Request specifier mismatch");

            // 4. Check for path traversal - resolved path should not escape project structure
            // This is a critical security invariant mentioned in the bead
            // We validate that the path is absolute and doesn't contain obvious traversal patterns
            assert!(!outcome.resolved_path.contains("../"),
                   "Resolved path contains traversal patterns: {}", outcome.resolved_path);
            assert!(!outcome.resolved_path.contains("..\\"),
                   "Resolved path contains Windows traversal patterns: {}", outcome.resolved_path);

            // 5. Traces should be present and non-empty
            assert!(!outcome.traces.is_empty(), "Resolution should produce traces");
        }
        Err(error) => {
            // Validate error invariants:
            // 1. Error should have a non-empty message
            assert!(!error.message.is_empty(), "Error message should not be empty");

            // 2. Error should have stable error code
            let stable_code = error.code.stable_code();
            assert!(!stable_code.is_empty(), "Error code should have stable representation");

            // 3. Traces should be present (even for errors)
            assert!(!error.traces.is_empty(), "Error should produce traces");
        }
    }

    // Test edge cases that could cause infinite loops or exponential behavior
    if data.len() < 100 {
        test_edge_cases(&resolver, &context);
    }
});

fn fuzz_config(data: &[u8]) -> TsModuleResolutionConfig {
    let mut config = TsModuleResolutionConfig::default();

    // Fuzz project root - include potential path traversal attempts
    config.project_root = fuzz_path(data, 0);

    // Fuzz base URL
    config.base_url = fuzz_path(data, 1);

    // Fuzz resolution mode
    config.mode = if byte(data, 2) % 2 == 0 {
        TsModuleResolutionMode::Node
    } else {
        TsModuleResolutionMode::NodeNext
    };

    // Fuzz path aliases - potential for wildcard expansion attacks
    for i in 0..4 {
        let pattern = fuzz_specifier(data, 10 + i * 2);
        let targets = vec![fuzz_path(data, 10 + i * 2 + 1)];
        if !pattern.is_empty() {
            config.paths.insert(pattern, targets);
        }
    }

    // Fuzz condition lists
    config.import_conditions = fuzz_string_list(data, 20, 4);
    config.require_conditions = fuzz_string_list(data, 25, 4);

    // Fuzz extensions
    config.import_extensions = fuzz_extension_list(data, 30);
    config.require_extensions = fuzz_extension_list(data, 35);

    config
}

fn fuzz_files(data: &[u8]) -> BTreeSet<String> {
    let mut files = BTreeSet::new();

    // Add some realistic files
    for i in 0..8 {
        let file_path = fuzz_path(data, 40 + i);
        if !file_path.is_empty() {
            files.insert(file_path);
        }
    }

    files
}

fn fuzz_packages(data: &[u8]) -> BTreeMap<String, TsPackageDefinition> {
    let mut packages = BTreeMap::new();

    // Add fuzzed package definitions - potential for scoped package attacks
    for i in 0..4 {
        let name = fuzz_package_name(data, 50 + i);
        if !name.is_empty() {
            let package_root = fuzz_path(data, 60 + i);
            let export_key = fuzz_string(data, 55 + i, 16);
            let mut export_target = TsPackageExportTarget::default();
            export_target.fallback_target = Some(fuzz_path(data, 65 + i));

            let package = TsPackageDefinition::new(name.clone(), package_root)
                .with_export(export_key, export_target);
            packages.insert(name, package);
        }
    }

    packages
}

fn fuzz_request(data: &[u8]) -> TsModuleRequest {
    let specifier = fuzz_specifier(data, 70);
    let style = if byte(data, 71) % 2 == 0 {
        TsRequestStyle::Import
    } else {
        TsRequestStyle::Require
    };

    let mut request = TsModuleRequest::new(specifier, style);

    // Sometimes add a referrer for relative resolution testing
    if byte(data, 72) % 3 == 0 {
        request = request.with_referrer(fuzz_path(data, 73));
    }

    request
}

fn fuzz_context(data: &[u8]) -> TsResolutionContext {
    TsResolutionContext::new(
        fuzz_string(data, 80, 32),
        fuzz_string(data, 81, 32),
        fuzz_string(data, 82, 32),
    )
}

fn fuzz_specifier(data: &[u8], seed: usize) -> String {
    let patterns = [
        "",                          // Empty specifier
        ".",                         // Current directory
        "..",                        // Parent directory
        "./relative",                // Relative path
        "../../../etc/passwd",       // Path traversal attempt
        "/absolute/path",            // Absolute path
        "@scoped/package",           // Scoped package
        "@/alias",                   // Alias with scope-like syntax
        "package/subpath",           // Package subpath
        "🚀/unicode",                // Unicode in path
        "very-long-name".repeat(20), // Long specifier
        "with space/path",           // Space in path
        "null\x00byte",              // Null byte
        "../../..\\..\\windows",     // Mixed separators
        "@scoped/../traverse",       // Scoped package traversal
        "**/glob",                   // Glob patterns
        "package?query=1",           // Query string
        "package#fragment",          // Fragment
    ];

    let index = byte(data, seed) % patterns.len();
    let base = patterns[index];

    // Sometimes append random data for novel inputs
    if byte(data, seed + 1) % 4 == 0 {
        let suffix = fuzz_string(data, seed + 2, 32);
        format!("{}{}", base, suffix)
    } else {
        base.to_string()
    }
}

fn fuzz_path(data: &[u8], seed: usize) -> String {
    let patterns = [
        "/",
        "/home/user",
        "/tmp",
        "/usr/lib/node_modules",
        "/project/src",
        "./relative",
        "../parent",
        "",
        "/very/deep/nested/path/that/goes/on/and/on",
        "/with spaces/path",
        "/🌟/unicode/path",
    ];

    let index = byte(data, seed) % patterns.len();
    patterns[index].to_string()
}

fn fuzz_package_name(data: &[u8], seed: usize) -> String {
    let patterns = [
        "package",
        "@scope/package",
        "@/malformed",
        "@scope/",
        "/@scope",
        "",
        "UPPERCASE",
        "with-dash",
        "with_underscore",
        "123numeric",
        "🎯unicode",
    ];

    let index = byte(data, seed) % patterns.len();
    patterns[index].to_string()
}

fn fuzz_string(data: &[u8], seed: usize, max_len: usize) -> String {
    let start = seed % data.len();
    let len = (byte(data, seed) as usize) % max_len.min(16);

    data.iter()
        .skip(start)
        .take(len)
        .map(|&b| char::from(b.wrapping_add(32) % 95 + 32)) // Printable ASCII
        .collect()
}

fn fuzz_string_list(data: &[u8], seed: usize, max_items: usize) -> Vec<String> {
    let count = (byte(data, seed) as usize) % max_items;
    (0..count)
        .map(|i| fuzz_string(data, seed + i + 1, 16))
        .filter(|s| !s.is_empty())
        .collect()
}

fn fuzz_extension_list(data: &[u8], seed: usize) -> Vec<String> {
    let extensions = [".ts", ".js", ".mjs", ".cjs", ".tsx", ".jsx", "/index.ts", "/index.js"];
    let count = (byte(data, seed) as usize) % 6;
    (0..count)
        .map(|i| {
            let idx = byte(data, seed + i + 1) % extensions.len();
            extensions[idx].to_string()
        })
        .collect()
}

fn test_edge_cases(resolver: &DeterministicTsModuleResolver, context: &TsResolutionContext) {
    let edge_cases = [
        // Empty and minimal cases
        TsModuleRequest::new("", TsRequestStyle::Import),
        TsModuleRequest::new(".", TsRequestStyle::Import),
        TsModuleRequest::new("..", TsRequestStyle::Import),

        // Path traversal attempts
        TsModuleRequest::new("../../../etc/passwd", TsRequestStyle::Import),
        TsModuleRequest::new("..\\..\\..\\windows\\system32", TsRequestStyle::Import),

        // Unicode edge cases
        TsModuleRequest::new("🚀", TsRequestStyle::Import),
        TsModuleRequest::new("\u{FEFF}package", TsRequestStyle::Import), // BOM
        TsModuleRequest::new("package\u{0000}", TsRequestStyle::Import), // Null byte

        // Scoped package edge cases
        TsModuleRequest::new("@", TsRequestStyle::Import),
        TsModuleRequest::new("@/", TsRequestStyle::Import),
        TsModuleRequest::new("@scope/", TsRequestStyle::Import),
        TsModuleRequest::new("/@scope/package", TsRequestStyle::Import),
    ];

    for request in edge_cases {
        let _result = resolver.resolve(&request, context);
        // Should not panic on any edge case
    }
}

fn normalize_path(path: &str) -> String {
    // Simple path normalization for validation
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{}", path)
    }
}

fn byte(data: &[u8], index: usize) -> u8 {
    if data.is_empty() {
        return 0;
    }
    data[index % data.len()]
}