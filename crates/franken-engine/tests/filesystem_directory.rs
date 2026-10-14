//! Directory cursors through the real shared runtime and gated host provider.
//! Node-host testing of the JS adapter is not evidence these Rust tests pass.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use frankenengine_engine::baseline_interpreter::LaneChoice;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, LabFixtureExecutionOrchestratorExt, OrchestratorConfig,
};
use frankenengine_extension_host::host_io::{
    FsOperation, HostIoCapability, HostIoOutcome, HostIoRecorder, HostIoRequest,
    InMemoryHostIoTranscript, SandboxedHostIo,
};

type Run = (Vec<String>, Vec<(HostIoRequest, HostIoOutcome)>);

fn run(source: &str, root: &Path, caps: &[&str], lane: LaneChoice) -> Result<Run, String> {
    let provider = Arc::new(SandboxedHostIo::with_root(root).expect("sandbox provider"));
    let recording = Arc::new(InMemoryHostIoTranscript::recording());
    let recorder: Arc<dyn HostIoRecorder> = recording.clone();
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig {
        force_lane: Some(lane),
        ..OrchestratorConfig::default()
    });
    orchestrator.set_host_io(provider, Some(recorder));
    let mut capabilities = vec!["vm_dispatch", "heap_allocate", "builtin", "console"];
    capabilities.extend_from_slice(caps);
    let package = ExtensionPackage {
        extension_id: "filesystem-directory".into(),
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

fn fixture(root: &Path) {
    std::fs::create_dir_all(root.join("tree/sub/deep")).unwrap();
    for (file, bytes) in [("tree/a.txt", "a"), ("tree/sub/b.txt", "b"), ("tree/sub/deep/c.txt", "c")] {
        std::fs::write(root.join(file), bytes).unwrap();
    }
}

#[test]
fn recursive_directory_iteration_completes_with_only_native_read_effects() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().unwrap();
        fixture(root.path());
        let (lines, effects) = run(
            "const { opendir }=require('node:fs/promises'); (async function(){\
             const dir=await opendir('tree',{recursive:true}); const files=[];\
             for await(const entry of dir){if(entry.isFile())files.push(entry.parentPath+'/'+entry.name);}\
             console.log(files.sort().join(','));try{dir.readSync();}catch(e){console.log(e.code);}})();",
            root.path(), &["fs_read"], lane,
        ).expect("native directory completion");
        assert_eq!(lines, ["tree/a.txt,tree/sub/b.txt,tree/sub/deep/c.txt", "ERR_DIR_CLOSED"]);
        let directories = effects.iter().filter(|(request, _)| matches!(request,
            HostIoRequest::FsMeta { operation: FsOperation::ReadDir, .. })).count();
        assert_eq!(directories, 3);
        assert!(effects.iter().all(|(request, _)| request.required_capability() == HostIoCapability::FsRead));
        assert_eq!(std::fs::read(root.path().join("tree/sub/deep/c.txt")).unwrap(), b"c");
    }
}

#[test]
fn early_return_releases_the_cursor_without_prefetching_child_directories() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().unwrap();
        fixture(root.path());
        let (lines, effects) = run(
            "const fs=require('fs');const WeakMap='guest';const String='guest';\
             (async function(){const dir=await fs.promises.opendir('tree',{recursive:true});\
             for await(const entry of dir){break;}try{dir.readSync();}catch(e){console.log(e.code);}})();",
            root.path(), &["fs_read"], lane,
        ).expect("early cleanup and protected realm helpers");
        assert_eq!(lines, ["ERR_DIR_CLOSED"]);
        assert_eq!(effects.iter().filter(|(request, _)| matches!(request,
            HostIoRequest::FsMeta { operation: FsOperation::ReadDir, .. })).count(), 1);
    }
}

#[test]
fn accepted_reads_finish_before_close_and_sync_calls_cannot_race_them() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().unwrap();
        fixture(root.path());
        let (lines, _) = run(
            "const fs=require('fs');const dir=fs.opendirSync('tree');\
             const a=dir.read(),b=dir.read(),c=dir.read();const closing=dir.close();\
             try{dir.closeSync();}catch(e){console.log(e.code);}\
             Promise.all([a,b,c]).then(async values=>{console.log(values.filter(Boolean).length,values[2]===null);\
             await closing;try{dir.read();}catch(e){console.log(e.code);}});",
            root.path(), &["fs_read"], lane,
        ).expect("queued directory operations complete");
        assert_eq!(lines, ["ERR_DIR_CONCURRENT_OPERATION", "2 true", "ERR_DIR_CLOSED"]);
    }
}

#[test]
fn directory_iteration_never_infers_read_authority_from_write_permission() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().unwrap();
        fixture(root.path());
        let error = run("require('fs').opendirSync('tree');", root.path(), &["fs_write"], lane)
            .expect_err("directory acquisition requires FsRead");
        assert!(error.to_ascii_lowercase().contains("capabil"), "{error}");
    }
}
