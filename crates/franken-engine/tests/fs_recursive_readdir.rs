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

#[test]
fn callback_directory_cursor_reuses_read_authority_and_completes_recursive_work() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().unwrap();
        tree(root.path());
        let (lines, effects) = run(
            "const fs=require('node:fs');const queueMicrotask='guest';const Promise='guest'; \
             let sync=true;fs.opendir('tree',{recursive:true},(error,dir)=>{ \
               if(error)throw error;console.log('OPEN',sync,dir instanceof fs.Dir); \
               const files=[];function next(error,entry){if(error)throw error; \
                 if(entry===null){dir.close(error=>{if(error)throw error; \
                   console.log(files.sort().join('|'));console.log('CURSOR_COMPLETE');});return;} \
                 if(entry.isFile())files.push(entry.parentPath+'/'+entry.name);dir.read(next); \
               }dir.read(next);});sync=false;",
            root.path(), &["fs_read"], lane, ParseGoal::Script,
        ).expect("callback enumeration must reach the native queue and complete");
        assert_eq!(lines, ["OPEN false true", "tree/a/deep/alpha.json|tree/b/beta.json|tree/top.txt", "CURSOR_COMPLETE"]);
        assert_eq!(effects.iter().filter(|(request, _)| matches!(request,
            HostIoRequest::FsMeta { operation: FsOperation::ReadDir, .. })).count(), 4);
        assert!(effects.iter().all(|(request, _)| request.required_capability()
            == frankenengine_extension_host::host_io::HostIoCapability::FsRead));
    }
}

#[test]
fn callback_and_promise_directory_reads_share_one_position_and_close_barrier() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().unwrap();
        tree(root.path());
        let (lines, _) = run(
            "const fs=require('fs');fs.opendir('tree',(error,dir)=>{if(error)throw error; \
               const values=[];dir.read((error,entry)=>{if(error)throw error;values.push(entry.name);}); \
               const second=dir.read().then(entry=>values.push(entry.name)); \
               dir.read((error,entry)=>{if(error)throw error;values.push(entry.name);}); \
               dir.read((error,entry)=>{if(error)throw error;console.log('EOF',entry===null);}); \
               dir.close(error=>{if(error)throw error;console.log(values.sort().join('|')); \
                 try{dir.read();}catch(error){console.log(error.code);}console.log('MIXED_COMPLETE');}); \
             });",
            root.path(), &["fs_read"], lane, ParseGoal::Script,
        ).expect("callback and Promise requests must drain before close");
        assert_eq!(lines, ["EOF true", "a|b|top.txt", "ERR_DIR_CLOSED", "MIXED_COMPLETE"]);
    }
}

#[test]
fn esm_callback_open_supports_promisification_and_reports_missing_roots() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().unwrap();
        tree(root.path());
        let (lines, _) = run(
            "import {opendir} from 'node:fs';import {promisify} from 'node:util'; \
             (async()=>{const open=promisify(opendir);try{await open('absent');} \
               catch(error){console.log(error.code);}const dir=await open('tree'); \
               const entry=await promisify(dir.read).call(dir);console.log(typeof entry.name); \
               await promisify(dir.close).call(dir);console.log('ESM_CURSOR_COMPLETE');})();",
            root.path(), &["fs_read"], lane, ParseGoal::Module,
        ).expect("ESM and promisification must invoke the same directory owner");
        assert_eq!(lines, ["ENOENT", "string", "ESM_CURSOR_COMPLETE"]);
    }
}

#[test]
fn callback_open_rejects_invalid_callbacks_before_effects_without_adding_authority() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().unwrap();
        tree(root.path());
        let (lines, effects) = run(
            "const fs=require('fs');try{fs.opendir('tree',{},null);} \
             catch(error){console.log(error.code);}console.log('PREFLIGHT_COMPLETE');",
            root.path(), &[], lane, ParseGoal::Script,
        ).expect("callback validation is not a filesystem operation");
        assert_eq!(lines, ["ERR_INVALID_ARG_TYPE", "PREFLIGHT_COMPLETE"]);
        assert!(effects.is_empty());
        let error = run("require('fs').opendir('tree',()=>{});", root.path(),
            &["fs_write"], lane, ParseGoal::Script)
            .expect_err("asynchronous acquisition still requires read authority");
        assert!(error.to_ascii_lowercase().contains("capabil"), "{error}");
    }
}
