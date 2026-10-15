//! Recursive discovery through the shared sandboxed engine. Host-only JS tests
//! do not establish that these native execution tests have passed.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::LaneChoice;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, LabFixtureExecutionOrchestratorExt, OrchestratorConfig,
};
use frankenengine_extension_host::host_io::{
    FsOperation, HostIoOutcome, HostIoRecorder, HostIoRequest, InMemoryHostIoTranscript,
    SandboxedHostIo,
};

type Run = (Vec<String>, Vec<(HostIoRequest, HostIoOutcome)>);

fn run(source: &str, root: &Path, caps: &[&str], lane: LaneChoice, goal: ParseGoal) -> Result<Run, String> {
    let provider = Arc::new(SandboxedHostIo::with_root(root).expect("sandbox provider"));
    let recording = Arc::new(InMemoryHostIoTranscript::recording());
    let recorder: Arc<dyn HostIoRecorder> = recording.clone();
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig {
        force_lane: Some(lane),
        parse_goal: goal,
        ..OrchestratorConfig::default()
    });
    orchestrator.set_host_io(provider, Some(recorder));
    let mut capabilities = vec!["vm_dispatch", "heap_allocate", "builtin", "console"];
    capabilities.extend_from_slice(caps);
    let package = ExtensionPackage {
        extension_id: "recursive-readdir".into(),
        source: source.into(),
        source_file: None,
        module_root: None,
        capabilities: capabilities.into_iter().map(str::to_string).collect(),
        version: "1.0.0".into(),
        metadata: BTreeMap::new(),
    };
    let result = orchestrator.execute(&package).map_err(|error| format!("{error:?}"))?;
    Ok((result.console_output.into_iter().map(|entry| entry.message).collect(), recording.entries()))
}

fn tree(root: &Path) {
    std::fs::create_dir_all(root.join("tree/a/deep")).unwrap();
    std::fs::create_dir_all(root.join("tree/b")).unwrap();
    std::fs::write(root.join("tree/a/deep/alpha.json"), b"{}").unwrap();
    std::fs::write(root.join("tree/b/beta.json"), b"{}").unwrap();
    std::fs::write(root.join("tree/top.txt"), b"top").unwrap();
}

#[test]
fn inline_namespace_and_named_calls_all_visit_the_complete_tree_without_write_authority() {
    let expected = "a|a/deep|a/deep/alpha.json|b|b/beta.json|top.txt";
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        for (prefix, call) in [
            ("", "require('fs').readdirSync"),
            ("const fs = require('node:fs');", "fs.readdirSync"),
            ("const {readdirSync: scan} = require('fs');", "scan"),
        ] {
            let root = tempfile::tempdir().unwrap(); tree(root.path());
            let source = format!("{prefix} console.log({call}('tree', {{recursive:true}}).sort().join('|'));");
            let (lines, effects) = run(&source, root.path(), &["fs_read"], lane, ParseGoal::Script)
                .expect("recursive collector must not be erased by synchronous lowering");
            assert_eq!(lines, [expected]);
            assert_eq!(effects.iter().filter(|(request, _)| matches!(request,
                HostIoRequest::FsMeta { operation: FsOperation::ReadDir, .. })).count(), 4);
        }
    }
}

#[test]
fn esm_promise_discovery_protects_globals_and_exposes_lexical_parent_paths() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().unwrap(); tree(root.path());
        let (lines, _) = run(
            "import { readdir } from 'node:fs/promises'; const Object='guest'; const Array='guest'; \
             readdir('tree',{recursive:true,withFileTypes:true}).then(entries=>{ \
               const files=entries.filter(e=>e.isFile()).map(e=>e.parentPath+'/'+e.name).sort(); \
               console.log(files.join('|')); console.log('DISCOVERY_COMPLETE'); \
             });",
            root.path(), &["fs_read"], lane, ParseGoal::Module,
        ).expect("ESM uses the same directory collector");
        assert_eq!(lines, ["tree/a/deep/alpha.json|tree/b/beta.json|tree/top.txt", "DISCOVERY_COMPLETE"]);
    }
}

#[test]
fn callback_discovery_completes_and_failure_never_reports_a_partial_array() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().unwrap(); tree(root.path());
        let (lines, _) = run(
            "const fs=require('fs'); fs.readdir('tree',{recursive:true},(error,entries)=>{ \
               if(error) throw error; console.log(entries.sort().join('|')); \
               fs.readdir('absent',{recursive:true},(failure,partial)=>{ \
                 console.log(failure.code,typeof partial); console.log('CALLBACK_COMPLETE'); \
               }); \
             });",
            root.path(), &["fs_read"], lane, ParseGoal::Script,
        ).expect("callback errors and complete success");
        assert_eq!(lines, ["a|a/deep|a/deep/alpha.json|b|b/beta.json|top.txt", "ENOENT undefined", "CALLBACK_COMPLETE"]);
    }
}

#[cfg(unix)]
#[test]
fn directory_aliases_remain_distinct_but_ancestor_cycles_fail_explicitly() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().unwrap(); tree(root.path());
        std::os::unix::fs::symlink("a", root.path().join("tree/alias")).unwrap();
        let (lines, _) = run(
            "const fs=require('fs'); const names=fs.readdirSync('tree',{recursive:true}); \
             console.log(names.includes('alias/deep/alpha.json'),names.includes('a/deep/alpha.json'));",
            root.path(), &["fs_read"], lane, ParseGoal::Script,
        ).expect("internal directory symlink aliases");
        assert_eq!(lines, ["true true"]);
        std::os::unix::fs::symlink("..", root.path().join("tree/a/loop")).unwrap();
        let (lines, _) = run(
            "try { require('fs').readdirSync('tree',{recursive:true}); console.log('UNEXPECTED'); } \
             catch(error) { console.log(error.code); }",
            root.path(), &["fs_read"], lane, ParseGoal::Script,
        ).expect("explicit cycle failure");
        assert_eq!(lines, ["ERR_FS_DIR_CYCLE"]);
    }
}

#[test]
fn write_authority_does_not_authorize_recursive_discovery() {
    let root = tempfile::tempdir().unwrap(); tree(root.path());
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let error = run("require('fs').readdirSync('tree',{recursive:true});", root.path(),
            &["fs_write"], lane, ParseGoal::Script).expect_err("read authority is still required");
        assert!(error.to_ascii_lowercase().contains("capabil"), "{error}");
    }
}
