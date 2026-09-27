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

#[test]
fn private_imports_share_condition_pattern_selection_and_module_identity() {
    assert_output(
        &[
            ("package.json", r##"{"imports":{"#value":{"import":"./wrong.cjs","require":"./value.cjs","default":"./wrong.cjs"},"#utils/*":"./lib/*.cjs","#utils/special/*":"./special/*.cjs","#fallback":[null,"../invalid.cjs",{"browser":"./wrong.cjs"},"./value.cjs"]}}"##),
            ("app.cjs", "const a = require('#value'); console.log(a === require('./value.cjs'), a === require('#fallback')); console.log(require('#utils/item'), require('#utils/special/item'));"),
            ("value.cjs", "console.log('once'); module.exports = {value: 7};"),
            ("lib/item.cjs", "module.exports = 'general';"),
            ("special/item.cjs", "module.exports = 'specific';"),
            ("wrong.cjs", "throw 'wrong target';"),
        ],
        "app.cjs",
        &["once", "true true", "general specific"],
    );
}

#[test]
fn external_private_imports_resolve_from_the_defining_package() {
    assert_output(
        &[
            ("package.json", r##"{"imports":{"#dependency":"dep/feature"}}"##),
            ("nested/app.cjs", "console.log(require('#dependency'));"),
            ("node_modules/dep/package.json", r#"{"exports":{"./feature":{"require":"./feature.cjs","default":"./wrong.cjs"}}}"#),
            ("node_modules/dep/feature.cjs", "module.exports = 'owner-dependency';"),
            ("nested/node_modules/dep/package.json", r#"{"exports":{"./feature":"./feature.cjs"}}"#),
            ("nested/node_modules/dep/feature.cjs", "throw 'wrong requesting-directory dependency';"),
        ],
        "nested/app.cjs",
        &["owner-dependency"],
    );
}

#[test]
fn imports_can_target_package_self_exports_without_a_second_instance() {
    assert_output(
        &[
            ("package.json", r##"{"name":"@scope/self","exports":{"./value":"./value.cjs"},"imports":{"#value":"@scope/self/value"}}"##),
            ("app.cjs", "const value = require('#value'); console.log(value === require('@scope/self/value'), value === require('./value.cjs'));"),
            ("value.cjs", "console.log('once'); module.exports = {};"),
        ],
        "app.cjs",
        &["once", "true true"],
    );
}

#[test]
fn nearest_private_import_map_controls_each_loaded_module() {
    assert_output(
        &[
            ("package.json", r##"{"imports":{"#value":"./outer.cjs"}}"##),
            ("app.cjs", "console.log(require('#value'), require('./nested/entry.cjs'));"),
            ("outer.cjs", "module.exports = 'outer';"),
            ("nested/package.json", r##"{"imports":{"#value":"./inner.cjs"}}"##),
            ("nested/entry.cjs", "module.exports = require('#value');"),
            ("nested/inner.cjs", "module.exports = 'inner';"),
        ],
        "app.cjs",
        &["outer inner"],
    );
}

#[test]
fn private_imports_do_not_inherit_through_empty_nested_scopes_or_node_modules() {
    assert_refused(
        &[
            ("package.json", r##"{"imports":{"#value":"./outer.cjs"}}"##),
            ("outer.cjs", "throw 'outer private value leaked';"),
            ("nested/package.json", r##"{"imports":{}}"##),
            ("nested/app.cjs", "require('#value');"),
        ],
        "nested/app.cjs",
        "is not defined",
    );
    assert_refused(
        &[
            ("package.json", r##"{"imports":{"#value":"./outer.cjs"}}"##),
            ("outer.cjs", "throw 'consumer private value leaked';"),
            ("app.cjs", "require('dependency');"),
            ("node_modules/dependency/index.js", "module.exports = require('#value');"),
        ],
        "app.cjs",
        "module not found",
    );
}

#[test]
fn excluded_private_imports_never_fall_back_to_files_or_installed_names() {
    assert_refused(
        &[
            ("package.json", r##"{"imports":{"#internal/*":"./lib/*.cjs","#internal/private/*":null}}"##),
            ("app.cjs", "require('#internal/private/secret');"),
            ("lib/private/secret.cjs", "throw 'private source loaded';"),
            ("node_modules/#internal/private/secret.js", "throw 'private fallback loaded';"),
        ],
        "app.cjs",
        "is not defined",
    );
}

#[test]
fn private_imports_use_exact_files_and_do_not_retry_missing_selected_targets() {
    for manifest in [
        r##"{"imports":{"#value":"./value"}}"##,
        r##"{"imports":{"#value":["./missing.cjs","./value.cjs"]}}"##,
        r##"{"imports":{"#value":["missing-package","./value.cjs"]}}"##,
    ] {
        assert_refused(
            &[
                ("package.json", manifest),
                ("app.cjs", "require('#value');"),
                ("value.cjs", "throw 'incorrect missing-target fallback';"),
                ("value.js", "throw 'incorrect extension probing';"),
            ],
            "app.cjs",
            "module not found",
        );
    }
}

#[test]
fn private_url_targets_decode_once_and_share_canonical_cache_entries() {
    assert_output(
        &[
            ("package.json", r##"{"imports":{"#value":"./lib/%76alue.cjs?query#fragment","#unicode":"./lib/%C3%A9.cjs","#percent":"./lib/%252e.cjs"}}"##),
            ("app.cjs", "console.log(require('#value') === require('./lib/value.cjs')); console.log(require('#unicode'), require('#percent'));"),
            ("lib/value.cjs", "console.log('once'); module.exports = {};"),
            ("lib/é.cjs", "module.exports = 'unicode';"),
            ("lib/%2e.cjs", "module.exports = 'percent';"),
        ],
        "app.cjs",
        &["once", "true", "unicode percent"],
    );
}

#[test]
fn invalid_import_names_and_encoded_traversals_are_refused() {
    for specifier in ["#", "#/x", "#all/", "#all/../escape", "#all/%2e%2e/escape", "#all/x%2fy", "#all/x%5cy"] {
        let source = format!("require({});", serde_json::to_string(specifier).expect("specifier"));
        assert_refused(
            &[
                ("package.json", r##"{"imports":{"#all/*":"./lib/*.cjs"}}"##),
                ("app.cjs", source.as_str()),
                ("escape.cjs", "throw 'escaped target executed';"),
                ("lib/x/y.cjs", "throw 'encoded separator executed';"),
            ],
            "app.cjs",
            "package",
        );
    }
}

#[test]
fn absent_imports_preserve_legacy_lookup_but_an_empty_map_is_authoritative() {
    for manifest in ["{}", r##"{"imports":null}"##] {
        assert_output(
            &[
                ("package.json", manifest),
                ("app.cjs", "console.log(require('#value'));"),
                ("node_modules/#value/index.js", "module.exports = 'legacy';"),
            ],
            "app.cjs",
            &["legacy"],
        );
    }
    assert_refused(
        &[
            ("package.json", r##"{"imports":{}}"##),
            ("app.cjs", "require('#value');"),
            ("node_modules/#value/index.js", "throw 'empty-map fallback';"),
        ],
        "app.cjs",
        "is not defined",
    );
}

#[test]
fn private_alias_cycles_use_the_module_cache_not_repeated_evaluation() {
    assert_output(
        &[
            ("package.json", r##"{"imports":{"#main":"./main.cjs","#again":"./main.cjs"}}"##),
            ("app.cjs", "const value = require('#main'); console.log(value.same, value.phase);"),
            ("main.cjs", "module.exports.phase = 'loading'; module.exports.same = require('#again') === module.exports; module.exports.phase = 'done';"),
        ],
        "app.cjs",
        &["true done"],
    );
}

#[test]
fn external_import_target_cannot_spoof_a_core_module_with_node_modules() {
    assert_refused(
        &[
            ("package.json", r##"{"imports":{"#core":"path"}}"##),
            ("app.cjs", "require('#core');"),
            ("node_modules/path/index.js", "throw 'core spoof loaded';"),
        ],
        "app.cjs",
        "Node core module",
    );
}
