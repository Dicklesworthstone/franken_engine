#![forbid(unsafe_code)]

//! Resolve real on-disk packages through the shipped CommonJS entry pipeline.
use std::path::Path;

use frankenengine_engine::baseline_interpreter::LaneChoice;
use frankenengine_engine::execution_orchestrator::LabFixtureExecutionOrchestratorExt as _;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig,
};

fn write_tree(root: &Path, files: &[(&str, &str)]) {
    for (name, source) in files {
        let path = root.join(name);
        std::fs::create_dir_all(path.parent().expect("fixture parent")).expect("fixture directory");
        std::fs::write(path, source).expect("fixture file");
    }
}

fn run(root: &Path, entry: &str, lane: LaneChoice) -> Result<Vec<String>, String> {
    let entry = root.join(entry);
    let package = ExtensionPackage {
        extension_id: "package-scope-regression".to_string(),
        source: std::fs::read_to_string(&entry).expect("entry source"),
        source_file: Some(entry.display().to_string()),
        module_root: Some(root.display().to_string()),
        capabilities: vec!["module_load".to_string(), "builtin".to_string()],
        version: "1.0.0".to_string(),
        metadata: Default::default(),
    };
    ExecutionOrchestrator::new(OrchestratorConfig {
        force_lane: Some(lane),
        commonjs_entry: true,
        ..OrchestratorConfig::default()
    })
    .execute(&package)
    .map(|result| result.console_output.into_iter().map(|line| line.message).collect())
    .map_err(|error| error.to_string())
}

fn assert_output(files: &[(&str, &str)], entry: &str, expected: &[&str]) {
    let root = tempfile::tempdir().expect("module root");
    write_tree(root.path(), files);
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let actual = run(root.path(), entry, lane)
            .unwrap_or_else(|error| panic!("{lane:?}: {error}"));
        assert_eq!(actual, expected, "{lane:?}");
    }
}

fn assert_refused(files: &[(&str, &str)], entry: &str, diagnostic: &str) {
    let root = tempfile::tempdir().expect("module root");
    write_tree(root.path(), files);
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let error = run(root.path(), entry, lane).expect_err("resolution must fail");
        assert!(error.contains(diagnostic), "{lane:?}: {error}");
    }
}

#[test]
fn self_reference_precedes_installed_namesake_and_shares_module_identity() {
    assert_output(
        &[
            ("package.json", r#"{"name":"self-pkg","exports":{".":{"require":"./lib/main.cjs","default":"./wrong.cjs"},"./feature/*":"./lib/*.cjs"}}"#),
            ("app.cjs", "const a = require('self-pkg'); const b = require('./lib/main.cjs'); console.log(a === b, require('self-pkg/feature/util'));"),
            ("lib/main.cjs", "console.log('initialized'); module.exports = {value: 7};"),
            ("lib/util.cjs", "module.exports = 9;"),
            ("wrong.cjs", "throw 'wrong condition';"),
            ("node_modules/self-pkg/index.js", "throw 'installed namesake';"),
        ],
        "app.cjs",
        &["initialized", "true 9"],
    );
}

#[test]
fn scoped_self_reference_uses_nearest_package_and_nested_module_location() {
    assert_output(
        &[
            ("app.cjs", "console.log(require('installed-name'));"),
            ("node_modules/installed-name/package.json", r#"{"name":"@scope/self","main":"src/start.cjs","exports":{".":"./src/start.cjs","./value":"./value.cjs"}}"#),
            ("node_modules/installed-name/src/start.cjs", "module.exports = require('@scope/self/value');"),
            ("node_modules/installed-name/value.cjs", "module.exports = 42;"),
        ],
        "app.cjs",
        &["42"],
    );
}

#[test]
fn unexported_self_reference_does_not_fall_back_to_an_installed_package() {
    assert_refused(
        &[
            ("package.json", r#"{"name":"self-pkg","exports":{".":"./main.cjs","./private/*":null}}"#),
            ("app.cjs", "require('self-pkg/private/secret');"),
            ("main.cjs", "module.exports = 1;"),
            ("node_modules/self-pkg/private/secret.js", "module.exports = 'must not load';"),
            ("private/secret.js", "module.exports = 'must not load';"),
        ],
        "app.cjs",
        "does not export",
    );
}

#[test]
fn self_reference_requires_an_exports_map_and_does_not_probe_extensions() {
    for manifest in [r#"{"name":"self-pkg","main":"own.cjs"}"#, r#"{"name":"self-pkg","exports":null}"#] {
        assert_output(
            &[
                ("package.json", manifest),
                ("app.cjs", "console.log(require('self-pkg'));"),
                ("own.cjs", "throw 'wrong self fallback';"),
                ("node_modules/self-pkg/index.js", "module.exports = 'installed';"),
            ],
            "app.cjs",
            &["installed"],
        );
    }
    assert_refused(
        &[
            ("package.json", r#"{"name":"self-pkg","exports":"./target"}"#),
            ("app.cjs", "require('self-pkg');"),
            ("target.js", "module.exports = 'wrong extension probing';"),
            ("node_modules/self-pkg/index.js", "module.exports = 'wrong fallback';"),
        ],
        "app.cjs",
        "module not found",
    );
}

#[test]
fn nearest_manifest_closes_scope_even_without_a_matching_name_or_exports() {
    assert_output(
        &[
            ("package.json", r#"{"name":"outer","exports":"./outer.cjs"}"#),
            ("outer.cjs", "throw 'outer scope leak';"),
            ("nested/package.json", "{}"),
            ("nested/app.cjs", "console.log(require('outer'));"),
            ("node_modules/outer/index.js", "module.exports = 'installed';"),
        ],
        "nested/app.cjs",
        &["installed"],
    );
}

#[test]
fn node_modules_boundary_does_not_leak_consumer_self_references() {
    assert_output(
        &[
            ("package.json", r#"{"name":"outer","exports":"./outer.cjs"}"#),
            ("outer.cjs", "throw 'consumer self leaked';"),
            ("app.cjs", "console.log(require('dependency'));"),
            ("node_modules/dependency/index.js", "module.exports = require('outer');"),
            ("node_modules/outer/index.js", "module.exports = 'installed';"),
        ],
        "app.cjs",
        &["installed"],
    );
}

#[test]
fn self_reference_cycles_share_the_existing_commonjs_cache() {
    assert_output(
        &[
            ("package.json", r#"{"name":"self-pkg","exports":"./main.cjs"}"#),
            ("app.cjs", "const value = require('self-pkg'); console.log(value.same, value.phase);"),
            ("main.cjs", "module.exports.phase = 'loading'; const again = require('self-pkg'); module.exports.same = again === module.exports; module.exports.phase = 'done';"),
        ],
        "app.cjs",
        &["true done"],
    );
}

#[test]
fn package_scope_does_not_cross_the_declared_module_root() {
    let outer = tempfile::tempdir().expect("outer fixture");
    write_tree(outer.path(), &[
        ("package.json", r#"{"name":"outer","exports":"./target.cjs"}"#),
        ("target.cjs", "throw 'root escaped';"),
        ("sandbox/app.cjs", "console.log(require('outer'));"),
        ("sandbox/node_modules/outer/index.js", "module.exports = 'bounded';"),
    ]);
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(run(&outer.path().join("sandbox"), "app.cjs", lane).expect("bounded resolution"), ["bounded"]);
    }
}

#[cfg(unix)]
#[test]
fn self_reference_rejects_symlink_targets_outside_the_module_root() {
    let root = tempfile::tempdir().expect("module root");
    let outside = tempfile::tempdir().expect("outside fixture");
    write_tree(root.path(), &[
        ("package.json", r#"{"name":"self-pkg","exports":"./escape.cjs"}"#),
        ("app.cjs", "require('self-pkg');"),
    ]);
    write_tree(outside.path(), &[("target.cjs", "throw 'outside executed';")]);
    std::os::unix::fs::symlink(outside.path().join("target.cjs"), root.path().join("escape.cjs")).expect("symlink");
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let error = run(root.path(), "app.cjs", lane).expect_err("escape must fail");
        assert!(error.contains("escapes module root"), "{lane:?}: {error}");
    }
}
