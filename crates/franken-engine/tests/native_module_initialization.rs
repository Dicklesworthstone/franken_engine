//! First-use native module initialization through both interpreter profiles.
//! Run this target before claiming native correctness or a startup speedup.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::sync::Arc;

use frankenengine_engine::baseline_interpreter::LaneChoice;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig,
};
use frankenengine_engine::runtime_config::RuntimeConfig;
use frankenengine_extension_host::host_io::{
    HostIoRecorder, InMemoryHostIoTranscript, SandboxedHostIo,
};

fn run(source: &str, lane: LaneChoice) -> Result<Vec<String>, String> {
    // Keep the ordinary budget. In particular, do not raise it just to make
    // the unused-module regression pass. No I/O, timer or loader grant.
    let mut orchestrator = ExecutionOrchestrator::try_new_lab_with_runtime_config(
        OrchestratorConfig {
            force_lane: Some(lane),
            ..OrchestratorConfig::default()
        },
        RuntimeConfig::default(),
    )
    .expect("default test configuration");
    // Supply a real host boundary so a denied filesystem test cannot pass
    // merely because no host provider was installed.
    let root = tempfile::tempdir().expect("sandbox directory");
    std::fs::write(root.path().join("not-authorized"), "private").expect("fixture");
    let provider = Arc::new(SandboxedHostIo::with_root(root.path()).expect("sandbox"));
    let recorder: Arc<dyn HostIoRecorder> = Arc::new(InMemoryHostIoTranscript::recording());
    orchestrator.set_host_io(provider, Some(recorder));
    let package = ExtensionPackage {
        extension_id: "native-module-initialization".into(),
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
    let result = orchestrator.execute(&package).map_err(|error| format!("{error:?}"))?;
    Ok(result.console_output.into_iter().map(|entry| entry.message).collect())
}

fn loader(initializer: &str) -> String {
    include_str!("../src/lowering_pipeline/native_module_loader.js")
        .replacen("__franken_native_module_initializer", initializer, 1)
}

#[test]
fn native_loader_runs_at_first_use_and_preserves_successful_exports() {
    let source = format!(
        "let attempts = 0; function build() {{ attempts++; return {{ generation: attempts }}; }}\n\
         const load = {};\n\
         console.log(attempts);\n\
         const first = load(); first.changed = 7;\n\
         console.log(attempts, first === load(), load().changed);",
        loader("build()"),
    );
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(run(&source, lane).expect("first-use cache"), ["0", "1 true 7"]);
    }
}

#[test]
fn native_loader_retries_falsy_exceptions_and_caches_falsy_exports() {
    let source = format!(
        "let attempts = 0; function build() {{ if (++attempts === 1) throw null; return false; }}\n\
         const load = {};\n\
         try {{ load(); }} catch (error) {{ console.log(error === null); }}\n\
         console.log(load(), load(), attempts);",
        loader("build()"),
    );
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(run(&source, lane).expect("failure retry"), ["true", "false false 2"]);
    }
}

#[test]
fn native_loader_reentrant_failure_unwinds_without_poisoning_the_cache() {
    let source = format!(
        "let recursive = true; let attempts = 0;\n\
         function build() {{ attempts++; return recursive ? load() : 42; }}\n\
         const load = {};\n\
         try {{ load(); }} catch (error) {{ console.log(error.code); }}\n\
         recursive = false; console.log(load(), load(), attempts);",
        loader("build()"),
    );
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(
            run(&source, lane).expect("reentrant initialization"),
            ["ERR_NATIVE_MODULE_REENTRANT", "42 42 2"]
        );
    }
}

#[test]
fn uncalled_native_module_requires_do_not_consume_the_entry_initialization_budget() {
    let source = r#"
function optionalModules() {
  return [require('fs'), require('stream'), require('util'), require('assert'),
          require('events'), require('buffer'), require('string_decoder'),
          require('timers'), require('vm'), require('querystring'),
          require('stream/consumers')];
}
console.log(42);
"#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(run(source, lane).expect("unused module startup"), ["42"]);
    }
}

#[test]
fn actual_native_module_aliases_submodules_and_nested_requires_share_identity() {
    let source = r#"
function utilAgain() { return require('node:util'); }
const util = require('util');
util.userMarker = 17;
console.log(util === utilAgain(), utilAgain().userMarker,
            util.types === require('node:util/types'));
const buffer = require('buffer');
console.log(buffer === require('node:buffer'), buffer.Buffer === Buffer);
"#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(
            run(source, lane).expect("shared native modules"),
            ["true 17 true", "true true"]
        );
    }
}

#[test]
fn first_use_does_not_grant_filesystem_effect_authority() {
    // Taking the module as a value prevents the call-only alias optimizer
    // from replacing the entire program with its direct hostcall shortcut.
    let source = r#"
const fs = require('fs');
const alias = fs;
console.log(alias === fs);
alias.readFileSync('not-authorized', 'utf8');
"#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let error = run(source, lane).expect_err("a loader is not an fs:read grant");
        assert!(error.to_ascii_lowercase().contains("capabil"), "{error}");
    }
}
