//! First-use native module initialization through both interpreter profiles.
//! Run this target before claiming native correctness or a startup speedup.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::sync::Arc;

use frankenengine_engine::baseline_interpreter::LaneChoice;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig, OrchestratorResult,
};
use frankenengine_engine::lowering_pipeline::AmbientAuthorityGrant;
use frankenengine_engine::runtime_config::RuntimeConfig;
use frankenengine_extension_host::host_io::{
    HostIoRecorder, InMemoryHostIoTranscript, SandboxedHostIo,
};

fn run(source: &str, lane: LaneChoice) -> Result<Vec<String>, String> {
    run_with_argv(source, lane, AmbientAuthorityGrant::DenyAll, &[]).map(|result| {
        result
            .console_output
            .into_iter()
            .map(|entry| entry.message)
            .collect()
    })
}

fn run_with_argv(
    source: &str,
    lane: LaneChoice,
    ambient_grant: AmbientAuthorityGrant,
    argv: &[&str],
) -> Result<OrchestratorResult, String> {
    // Keep the ordinary budget. In particular, do not raise it just to make
    // the unused-module regression pass. No I/O, timer or loader grant.
    let mut orchestrator =
        ExecutionOrchestrator::try_new_lab_with_runtime_config_and_ambient_authority_grant(
            OrchestratorConfig {
                force_lane: Some(lane),
                ..OrchestratorConfig::default()
            },
            RuntimeConfig::default(),
            ambient_grant,
        )
        .expect("default test configuration");
    orchestrator.set_process_argv(argv.iter().map(|arg| (*arg).to_string()).collect());
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
    orchestrator
        .execute(&package)
        .map_err(|error| format!("{error:?}"))
}

fn loader(initializer: &str) -> String {
    include_str!("../src/lowering_pipeline/native_module_loader.js").replacen(
        "__franken_native_module_initializer",
        initializer,
        1,
    )
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
        assert_eq!(
            run(&source, lane).expect("first-use cache"),
            ["0", "1 true 7"]
        );
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
        assert_eq!(
            run(&source, lane).expect("failure retry"),
            ["true", "false false 2"]
        );
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

#[test]
fn util_explicit_arguments_and_assert_do_not_require_process_authority() {
    let source = r#"
const util = require('util');
const assert = require('assert/strict');
function Parent() {}
function Child() {}
util.inherits(Child, Parent);
assert.equal(new Child() instanceof Parent, true);
const result = util.parseArgs({ args: ['--mode=explicit'], options: { mode: { type: 'string' } } });
assert.equal(result.values.mode, 'explicit');
console.log(result.values.mode, util === require('node:util'));
"#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let result = run_with_argv(
            source,
            lane,
            AmbientAuthorityGrant::DenyAll,
            &["runtime", "app.cjs", "--mode=host"],
        )
        .expect("pure util and explicit argv do not exercise ambient authority");
        assert_eq!(result.console_output[0].message, "explicit true");
        assert!(
            result
                .ir4_witness
                .hostcall_decisions
                .iter()
                .all(|decision| {
                    decision.capability.0
                        != frankenengine_engine::capability::UTIL_PROCESS_ARGV_CAPABILITY
                        && decision.capability.0
                            != frankenengine_engine::capability::UTIL_PROCESS_EXEC_ARGV_CAPABILITY
                }),
            "an explicit args array must not invoke the host-input reader"
        );
    }
}

#[test]
fn util_default_arguments_are_denied_at_invocation_without_the_shape_grant() {
    for source in [
        "const util = require('util'); util.parseArgs({ allowPositionals: true });",
        "const parse = require('util').parseArgs; parse({ args: undefined, allowPositionals: true });",
    ] {
        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            let error = run_with_argv(
                source,
                lane,
                AmbientAuthorityGrant::DenyAll,
                &["runtime", "app.cjs", "private-argument"],
            )
            .expect_err("Builtin alone cannot read process arguments");
            assert!(error.contains("CapabilityDenied"), "{error}");
            assert!(error.contains("builtin:UtilProcessExecArgv"), "{error}");
            assert!(!error.contains("private-argument"), "{error}");
        }
    }
}

#[test]
fn util_default_arguments_read_the_live_process_and_ignore_guest_shadows() {
    let source = r#"
const util = require('util');
const options = { mode: { type: 'string' } };
const first = util.parseArgs({ options });
console.log(first.values.mode);
process.argv[2] = '--mode=changed';
console.log(util.parseArgs({ options }).values.mode, first.values.mode);
function withShadow(process) { return util.parseArgs({ options }).values.mode; }
console.log(withShadow({ argv: ['fake', 'fake', '--mode=forged'] }));
process.argv = ['runtime', 'script', '--mode=replaced'];
console.log(util.parseArgs({ options }).values.mode);
"#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let result = run_with_argv(
            source,
            lane,
            AmbientAuthorityGrant::TrustedProcessShape,
            &["runtime", "app.cjs", "--mode=original"],
        )
        .expect("explicit shape authority reads actual program argv");
        let output: Vec<_> = result
            .console_output
            .iter()
            .map(|entry| entry.message.as_str())
            .collect();
        assert_eq!(
            output,
            ["original", "changed original", "changed", "replaced"]
        );
        for tag in [
            frankenengine_engine::capability::UTIL_PROCESS_ARGV_CAPABILITY,
            frankenengine_engine::capability::UTIL_PROCESS_EXEC_ARGV_CAPABILITY,
        ] {
            let reads: Vec<_> = result
                .ir4_witness
                .hostcall_decisions
                .iter()
                .filter(|decision| decision.capability.0 == tag)
                .collect();
            assert_eq!(reads.len(), 4, "each runtime {tag} read retains a decision");
            assert!(reads.iter().all(|decision| decision.allowed));
        }
    }
}

#[test]
fn util_argv_reexecution_uses_serialized_invocation_inputs() {
    // franken_node captures this exact argv vector and restores it through
    // set_process_argv before offline execution. No host environment or CLI
    // argv is consulted, and the same inputs retain the same read decisions.
    let recorded_argv = vec!["runtime", "/captured/app.cjs", "--mode=captured", "tail"];
    let bytes = serde_json::to_vec(&recorded_argv).expect("capture argv");
    let replay_argv: Vec<String> = serde_json::from_slice(&bytes).expect("restore argv");
    let replay_refs: Vec<_> = replay_argv.iter().map(String::as_str).collect();
    let source = "const u=require('util'); const r=u.parseArgs({options:{mode:{type:'string'}},allowPositionals:true}); console.log(r.values.mode,r.positionals.join(','));";
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let original = run_with_argv(
            source,
            lane,
            AmbientAuthorityGrant::TrustedProcessShape,
            &recorded_argv,
        )
        .expect("original configured invocation");
        let replay = run_with_argv(
            source,
            lane,
            AmbientAuthorityGrant::TrustedProcessShape,
            &replay_refs,
        )
        .expect("reexecuted configured invocation");
        assert_eq!(original.console_output[0].message, "captured tail");
        assert_eq!(original.console_output, replay.console_output);
        assert_eq!(
            original.ir4_witness.hostcall_decisions,
            replay.ir4_witness.hostcall_decisions
        );
    }
}

#[test]
fn util_reader_does_not_authorize_raw_computed_or_environment_process_reads() {
    for source in [
        "require('util'); const alias=process; console.log(alias.argv);",
        "require('util'); const key='argv'; console.log(process[key]);",
        "require('util'); console.log(globalThis.process.argv);",
        "require('util'); console.log(process.env);",
        "require('util'); console.log(process.execArgv);",
    ] {
        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            let error = run_with_argv(
                source,
                lane,
                AmbientAuthorityGrant::TrustedProcessShape,
                &[],
            )
            .expect_err("the narrow reader must not broaden ambient authority");
            assert!(
                error.contains("AmbientAuthorityViolation"),
                "{source}: {error}"
            );
        }
    }
}
