//! A source binding named require must not be replaced by the fs facade.
//! These exercise the public parse/lower/execute path without filesystem grants.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, LabFixtureExecutionOrchestratorExt, OrchestratorConfig,
};

fn run(source: &str) -> Vec<String> {
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    let package = ExtensionPackage {
        extension_id: "fs-require-scope-regression".into(),
        source: source.into(),
        source_file: None,
        module_root: None,
        capabilities: ["vm_dispatch", "heap_allocate", "builtin", "console"]
            .into_iter()
            .map(str::to_string)
            .collect(),
        version: "1.0.0".into(),
        metadata: BTreeMap::new(),
    };
    orchestrator
        .execute(&package)
        .expect("lexical require runs without filesystem authority")
        .console_output
        .into_iter()
        .map(|entry| entry.message)
        .collect()
}

#[test]
fn loop_local_loaders_are_called_instead_of_the_filesystem_facade() {
    let output = run(
        r#"
        for (let require = name => 'for:' + name, i = 0; i < 1; i += 1) {
            console.log(require('fs'));
        }
        for (const require of [name => 'of:' + name]) {
            console.log(require('node:fs'));
        }
        for (const { require } of [{ require: name => 'pattern:' + name }]) {
            console.log(require('fs/promises'));
        }
        for (let require in { loader: true }) {
            try { require('node:fs/promises'); }
            catch (error) { console.log(error.name); }
        }
        "#,
    );
    assert_eq!(output, ["for:fs", "of:node:fs", "pattern:fs/promises", "TypeError"]);
}

#[test]
fn dynamic_require_getter_keeps_its_receiver_and_observable_lookup() {
    let output = run(
        r#"
        let gets = 0;
        const loader = {
            prefix: 'custom:',
            get require() {
                gets += 1;
                return function (name) { return this.prefix + name; };
            }
        };
        with (loader) { console.log(require('fs')); }
        console.log(gets);
        "#,
    );
    assert_eq!(output, ["custom:fs", "1"]);
}

#[test]
fn named_class_require_remains_the_class_not_a_module_loader() {
    let output = run(
        r#"
        const Loader = class require {
            static load() {
                try { require('fs'); }
                catch (error) { return error.name; }
                return 'wrong builtin substitution';
            }
        };
        console.log(Loader.load());
        "#,
    );
    assert_eq!(output, ["TypeError"]);
}

#[test]
fn lexical_for_of_source_keeps_the_loop_bindings_temporal_dead_zone() {
    let output = run(
        r#"
        try { for (let require of require('fs')) {} }
        catch (error) { console.log(error.name); }
        "#,
    );
    assert_eq!(output, ["ReferenceError"]);
}
