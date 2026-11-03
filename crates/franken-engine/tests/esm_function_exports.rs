#![forbid(unsafe_code)]

//! Execute live function-export mutations through the real source-to-runtime
//! pipeline and filesystem module loader on both native interpreter profiles.
//! Expected output was cross-checked with Node v24.22.1 on the same sources.

use std::path::Path;

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::LaneChoice;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig,
};

fn assert_module_output(root: &Path, entry: &str, expected: &[&str]) {
    let entry = root.join(entry);
    let package = ExtensionPackage {
        extension_id: "esm-function-exports".to_string(),
        source: std::fs::read_to_string(&entry).expect("entry source"),
        source_file: Some(entry.display().to_string()),
        module_root: Some(root.display().to_string()),
        capabilities: vec!["module_load".to_string(), "builtin".to_string()],
        version: "1.0.0".to_string(),
        metadata: Default::default(),
    };
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let mut runtime = ExecutionOrchestrator::try_new_lab(OrchestratorConfig {
            parse_goal: ParseGoal::Module,
            force_lane: Some(lane),
            ..OrchestratorConfig::default()
        })
        .expect("native test runtime");
        let result = runtime
            .execute(&package)
            .unwrap_or_else(|error| panic!("{lane} failed: {error}"));
        let lines: Vec<_> = result
            .console_output
            .iter()
            .map(|line| line.message.as_str())
            .collect();
        assert_eq!(lines, expected, "{lane}");
    }
}

/// A declaration that no closure captures still has a mutable export cell.
/// Re-publication at the end of module evaluation cannot repair observations
/// made by a self-import between the assignment and the end of the body.
#[test]
fn exported_function_reassignments_reach_self_imports_immediately() {
    let root = tempfile::tempdir().expect("temp dir");
    std::fs::write(
        root.path().join("self.mjs"),
        r#"import originalDefault, { current as observed, renamed } from './self.mjs';
import * as ns from './self.mjs';
export function current() { return 1; }
export { current as renamed, current as default };
console.log(observed(), renamed(), originalDefault(), ns.current(), ns.renamed(), ns.default());
current = function replacement() { return 2; };
console.log(observed(), renamed(), originalDefault(), ns.current(), ns.renamed(), ns.default());
try { observed = function () { return 9; }; }
catch (error) { console.log(error instanceof TypeError, observed(), current()); }
"#,
    )
    .expect("write self.mjs");
    assert_module_output(
        root.path(),
        "self.mjs",
        &["1 1 1 1 1 1", "2 2 2 2 2 2", "true 2 2"],
    );
}

#[test]
fn cyclic_barrels_and_import_closures_observe_function_reassignment() {
    let root = tempfile::tempdir().expect("temp dir");
    for (name, source) in [
        (
            "source.mjs",
            r#"import { current as throughStar, alias, read } from './barrel.mjs';
export function current() { return 'first'; }
console.log(throughStar(), alias(), read());
current = () => 'second';
console.log(throughStar(), alias(), read());
"#,
        ),
        (
            "barrel.mjs",
            r#"export * from './source.mjs';
export { current as alias } from './source.mjs';
import { current } from './source.mjs';
export function read() { return current(); }
"#,
        ),
    ] {
        std::fs::write(root.path().join(name), source).expect("write module");
    }
    assert_module_output(
        root.path(),
        "source.mjs",
        &["first first first", "second second second"],
    );
}

/// Scope-routed declarations must keep hoisting, closure identity and the
/// live binding when the writer itself is a closure of the exporting module.
#[test]
fn captured_exported_functions_remain_hoisted_and_live_after_evaluation() {
    let root = tempfile::tempdir().expect("temp dir");
    for (name, source) in [
        (
            "source.mjs",
            r#"import { current as early } from './source.mjs';
console.log(early());
export function current() { return 3; }
export function replace() { current = () => 4; }
"#,
        ),
        (
            "main.mjs",
            r#"import { current, replace } from './source.mjs';
import * as ns from './source.mjs';
const before = current;
const read = () => current();
replace();
console.log(before(), current(), ns.current(), read(), current === ns.current);
"#,
        ),
    ] {
        std::fs::write(root.path().join(name), source).expect("write module");
    }
    assert_module_output(root.path(), "main.mjs", &["3", "3 4 4 4 true"]);
}

#[test]
fn exported_generator_reassignment_keeps_the_instantiated_function_live() {
    let root = tempfile::tempdir().expect("temp dir");
    std::fs::write(
        root.path().join("self.mjs"),
        r#"import { values as observed } from './self.mjs';
console.log(observed().next().value);
export function* values() { yield 5; }
values = function* () { yield 6; };
console.log(observed().next().value);
"#,
    )
    .expect("write self.mjs");
    assert_module_output(root.path(), "self.mjs", &["5", "6"]);
}

#[test]
fn named_default_function_is_hoisted_and_remains_a_live_export() {
    let root = tempfile::tempdir().expect("temp dir");
    std::fs::write(
        root.path().join("self.mjs"),
        r#"import observed from './self.mjs';
console.log(observed());
export default function current() { return 7; }
current = () => 8;
console.log(observed(), current());
"#,
    )
    .expect("write self.mjs");
    assert_module_output(root.path(), "self.mjs", &["7", "8 8"]);
}

#[test]
fn async_function_reassignment_reaches_importers_before_jobs_run() {
    let root = tempfile::tempdir().expect("temp dir");
    std::fs::write(
        root.path().join("self.mjs"),
        r#"import { current as observed } from './self.mjs';
observed().then(value => console.log('before', value));
export async function current() { return 9; }
current = async () => 10;
observed().then(value => console.log('after', value));
"#,
    )
    .expect("write self.mjs");
    assert_module_output(root.path(), "self.mjs", &["before 9", "after 10"]);
}

#[test]
fn declaration_own_name_follows_the_outer_live_binding_after_reassignment() {
    let root = tempfile::tempdir().expect("temp dir");
    std::fs::write(
        root.path().join("self.mjs"),
        r#"import { current as observed } from './self.mjs';
export function current() { return current; }
const original = observed;
console.log(original() === observed);
current = function replacement() { return replacement; };
console.log(original() === current, observed === current, original() === observed);
const replacement = current;
current = () => 11;
console.log(original() === current, replacement() === replacement, observed());
"#,
    )
    .expect("write self.mjs");
    assert_module_output(
        root.path(),
        "self.mjs",
        &["true", "true true true", "true true 11"],
    );
}
