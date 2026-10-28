//! bd-9vouw.399: a module namespace object has the @@toStringTag data
//! property "Module" (not writable, enumerable or configurable), after its
//! exports in Reflect.ownKeys, on both the static and the dynamic import.
//! Expected lines are Node v22.2.0's output for the same file tree.

use std::path::Path;

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::execution_orchestrator::LabFixtureExecutionOrchestratorExt as _;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig,
};

fn run(root: &Path, entry: &str) -> Result<Vec<String>, String> {
    let entry = root.join(entry);
    let package = ExtensionPackage {
        extension_id: "esm-probe".to_string(),
        source: std::fs::read_to_string(&entry).expect("entry source"),
        source_file: Some(entry.display().to_string()),
        module_root: Some(root.display().to_string()),
        capabilities: vec!["module_load".to_string(), "builtin".to_string()],
        version: "1.0.0".to_string(),
        metadata: Default::default(),
    };
    ExecutionOrchestrator::new(OrchestratorConfig {
        parse_goal: ParseGoal::Module,
        ..OrchestratorConfig::default()
    })
    .execute(&package)
    .map(|result| {
        result
            .console_output
            .into_iter()
            .map(|line| line.message)
            .collect()
    })
    .map_err(|error| error.to_string())
}

#[test]
fn module_namespace_objects_are_tagged_module() {
    let root = tempfile::tempdir().expect("module root");
    let files: &[(&str, &str)] = &[
        (
            "dep.mjs",
            r#"export const x = 1;
export default function f() {}
"#,
        ),
        (
            "app.mjs",
            r#"import * as ns from "./dep.mjs";
const d = Object.getOwnPropertyDescriptor(ns, Symbol.toStringTag);
console.log(ns[Symbol.toStringTag], Object.prototype.toString.call(ns), d && d.value, d && d.writable, d && d.enumerable, d && d.configurable);
console.log(Object.keys(ns).join(), Reflect.ownKeys(ns).length, String(Reflect.ownKeys(ns)[2]), Symbol.toStringTag in ns);
import("./dep.mjs").then((m) => console.log(m === ns, m[Symbol.toStringTag]));
"#,
        ),
    ];
    for (name, source) in files {
        std::fs::write(root.path().join(name), source).expect("fixture file");
    }
    let lines = run(root.path(), "app.mjs").unwrap_or_else(|error| panic!("run failed: {error}"));
    assert_eq!(
        lines,
        [
            "Module [object Module] Module false false false",
            "default,x 3 Symbol(Symbol.toStringTag) true",
            "true Module",
        ]
    );
}

fn assert_module_output(files: &[(&str, &str)], expected: &[&str]) {
    let root = tempfile::tempdir().expect("module root");
    for (name, source) in files {
        std::fs::write(root.path().join(name), source).expect("fixture file");
    }
    let lines = run(root.path(), "app.mjs").unwrap_or_else(|error| panic!("run failed: {error}"));
    assert_eq!(lines, expected);
}

#[test]
fn source_module_namespaces_protect_exports_and_retain_live_values() {
    assert_module_output(
        &[
            (
                "dep.mjs",
                r#"export let count = 1;
export function inc() { count++; }
"#,
            ),
            (
                "app.mjs",
                r#"import * as ns from './dep.mjs';
import { count, inc } from './dep.mjs';
const d = Object.getOwnPropertyDescriptor(ns, 'count');
console.log(d.value, d.writable, d.enumerable, d.configurable);
console.log(Object.getPrototypeOf(ns) === null, Object.isExtensible(ns), Object.isSealed(ns), Object.isFrozen(ns));
let assigned = false;
try { ns.count = 99; } catch (e) { assigned = e instanceof TypeError; }
console.log(assigned, Reflect.set(ns, 'count', 1), Reflect.set(ns, 'count', 99), Reflect.deleteProperty(ns, 'count'));
console.log(Reflect.set(ns, 'extra', 1), Reflect.deleteProperty(ns, 'absent'), 'extra' in ns);
let copied = false;
try { Object.assign(ns, { count: 99 }); } catch (e) { copied = e instanceof TypeError; }
console.log(copied, ns.count, count, Object.seal(ns) === ns);
inc();
console.log(ns.count, count, Object.getOwnPropertyDescriptor(ns, 'count').value);
import('./dep.mjs').then(other => console.log(other === ns, other.count));
"#,
            ),
        ],
        &[
            "1 true true false",
            "true false true false",
            "true false false false",
            "false true false",
            "true 1 1 true",
            "2 2 2",
            "true 2",
        ],
    );
}

#[test]
fn namespace_definitions_use_same_value_without_changing_descriptors() {
    assert_module_output(
        &[
            (
                "dep.mjs",
                r#"export let count = 1;
export const nan = NaN;
export const negativeZero = -0;
export function inc() { count++; }
"#,
            ),
            (
                "app.mjs",
                r#"import * as ns from './dep.mjs';
console.log(Reflect.defineProperty(ns, 'count', {}), Reflect.defineProperty(ns, 'count', { value: 1 }), Reflect.defineProperty(ns, 'count', { value: 9 }));
console.log(Reflect.defineProperty(ns, 'count', { writable: false }), Reflect.defineProperty(ns, 'count', { enumerable: false }), Reflect.defineProperty(ns, 'count', { configurable: true }), Reflect.defineProperty(ns, 'count', { get() { return 1; } }));
console.log(Reflect.defineProperty(ns, 'nan', { value: NaN }), Reflect.defineProperty(ns, 'negativeZero', { value: -0 }), Reflect.defineProperty(ns, 'negativeZero', { value: 0 }));
console.log(Reflect.defineProperty(ns, 'absent', { value: 1 }), Reflect.defineProperty(ns, Symbol('extra'), { value: 1 }), Reflect.defineProperty(ns, Symbol.toStringTag, { value: 'Module' }), Reflect.defineProperty(ns, Symbol.toStringTag, { value: 'Fake' }));
let redefined = false;
let frozen = false;
try { Object.defineProperty(ns, 'count', { value: 9 }); } catch (e) { redefined = e instanceof TypeError; }
try { Object.freeze(ns); } catch (e) { frozen = e instanceof TypeError; }
ns.inc();
console.log(redefined, frozen, ns.count, Object.isFrozen(ns), Object.getOwnPropertyDescriptor(ns, 'count').writable);
console.log(Reflect.setPrototypeOf(ns, null), Reflect.setPrototypeOf(ns, {}), Object.getPrototypeOf(ns) === null);
"#,
            ),
        ],
        &[
            "true true false",
            "false false false false",
            "true true false",
            "false false true false",
            "true true 2 false true",
            "true false true",
        ],
    );
}

#[test]
fn namespace_proxies_obey_nonconfigurable_export_invariants() {
    // The transparent Proxy's [[Set]] delegates to the namespace and must
    // reject even SameValue. As in the receiver test below, this expectation
    // follows ES2020 9.4.6.9 rather than Node v24.22.1's ordinary receiver path.
    assert_module_output(
        &[
            ("dep.mjs", r#"export let count = 1;"#),
            (
                "app.mjs",
                r#"import * as ns from './dep.mjs';
const p = new Proxy(ns, {});
console.log(Reflect.set(p, 'count', 1), Reflect.defineProperty(p, 'count', { value: 1 }), Reflect.defineProperty(p, 'count', { value: 2 }), Reflect.deleteProperty(p, 'count'));
function attempt(f) { try { f(); return 'accepted'; } catch (e) { return e.name; } }
console.log(attempt(() => Object.keys(new Proxy(ns, { ownKeys() { return []; } }))), attempt(() => 'count' in new Proxy(ns, { has() { return false; } })), attempt(() => Reflect.deleteProperty(new Proxy(ns, { deleteProperty() { return true; } }), 'count')));
console.log(attempt(() => Object.isExtensible(new Proxy(ns, { isExtensible() { return true; } }))), attempt(() => Object.getPrototypeOf(new Proxy(ns, { getPrototypeOf() { return {}; } }))));
const fake = { count: 1, [Symbol.toStringTag]: 'Module' };
console.log(Reflect.set(fake, 'count', 2), Reflect.defineProperty(fake, 'extra', { value: 3 }), fake.count, fake.extra, Object.isExtensible(fake));
"#,
            ),
        ],
        &[
            "false true false false",
            "TypeError TypeError TypeError",
            "TypeError TypeError",
            "true true 2 3 true",
        ],
    );
}

#[test]
fn empty_namespaces_can_be_frozen_and_cycles_can_publish_after_prevention() {
    assert_module_output(
        &[
            ("empty.mjs", r#"export {};"#),
            (
                "self.mjs",
                r#"import * as self from './self.mjs';
console.log(Object.isExtensible(self), Reflect.preventExtensions(self), Reflect.set(self, 'injected', 1));
export let count = 7;
export function inc() { count++; }
console.log(self.count, Object.getOwnPropertyDescriptor(self, 'count').configurable);
"#,
            ),
            (
                "app.mjs",
                r#"import * as empty from './empty.mjs';
import * as self from './self.mjs';
console.log(Object.isExtensible(empty), Object.isSealed(empty), Object.isFrozen(empty), Object.freeze(empty) === empty, Object.keys(empty).length);
self.inc();
console.log(self.count, Object.isSealed(self), Object.keys(self).join(','));
"#,
            ),
        ],
        &[
            "false true false",
            "7 false",
            "false true true true 0",
            "8 true count,inc",
        ],
    );
}

/// ES2020 9.4.6.9 [[Set]] always returns false, including a distinct
/// receiver or an inherited namespace. Node v24.22.1 incorrectly takes an
/// ordinary receiver path here; these expectations follow the specification.
#[test]
fn namespace_set_rejects_distinct_receivers_and_inheritance() {
    assert_module_output(
        &[
            ("dep.mjs", r#"export const count = 1;"#),
            (
                "app.mjs",
                r#"import * as ns from './dep.mjs';
const receiver = {};
const child = Object.create(ns);
console.log(Reflect.set(ns, 'count', 2, receiver), Reflect.set(ns, 'new', 3, receiver), Object.keys(receiver).length);
console.log(Reflect.set(child, 'count', 2), Reflect.set(child, 'new', 3), child.count, Object.keys(child).length);
console.log(Reflect.set(new Proxy(ns, {}), 'count', 2, receiver), Object.keys(receiver).length, ns.count);
"#,
            ),
        ],
        &["false false 0", "false false 1 0", "false 0 1"],
    );
}
