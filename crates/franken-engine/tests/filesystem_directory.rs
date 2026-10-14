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

#[test]
fn glob_discovery_prunes_unreachable_and_excluded_trees_on_both_lanes() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().unwrap();
        fixture(root.path());
        std::fs::create_dir_all(root.path().join("unrelated/private")).unwrap();
        std::fs::write(root.path().join("unrelated/private/file.txt"), b"not read").unwrap();
        let (lines, effects) = run(
            "const fs=require('node:fs');const String='guest';const Object='guest';\
             console.log(fs.globSync(['tree/**/*.txt','tree/a.txt'],\
             {exclude:['tree/sub/deep/**']}).sort().join(','));",
            root.path(), &["fs_read"], lane,
        ).expect("glob uses the real protected filesystem factory");
        assert_eq!(lines, ["tree/a.txt,tree/sub/b.txt"]);
        let directories: Vec<_> = effects.iter().filter_map(|(request, _)| {
            match request {
                HostIoRequest::FsMeta { operation: FsOperation::ReadDir, path, .. } => Some(path),
                _ => None,
            }
        }).collect();
        assert_eq!(directories.len(), 3, "root, tree, and tree/sub only");
        assert!(directories.iter().all(|path| !path.contains("unrelated") && !path.ends_with("/deep")));
        assert!(effects.iter().all(|(request, _)| request.required_capability() == HostIoCapability::FsRead));
    }
}

#[test]
fn glob_async_iterator_returns_without_acquiring_unrequested_descendants() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().unwrap();
        fixture(root.path());
        let (lines, effects) = run(
            "const {glob}=require('fs/promises');(async function(){\
             const unopened=glob('tree/**');await unopened.return();\
             const scan=glob('tree/**',{withFileTypes:true});\
             const first=await scan.next();console.log(first.value.name,first.value.isDirectory());\
             await scan.return();console.log((await scan.next()).done);})();",
            root.path(), &["fs_read"], lane,
        ).expect("native async iterator cleanup and completion");
        assert_eq!(lines, ["tree true", "true"]);
        assert_eq!(effects.iter().filter(|(request, _)| matches!(request,
            HostIoRequest::FsMeta { operation: FsOperation::ReadDir, .. })).count(), 1);
    }
}

#[test]
fn glob_braces_ranges_and_async_iteration_produce_exact_completion_output() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().unwrap();
        fixture(root.path());
        let (lines, _) = run(
            "const fs=require('fs');(async function(){const files=[];\
             for await(const entry of fs.promises.glob('tree/{a,sub/[b-c]}.txt'))files.push(entry);\
             console.log('GLOB_COMPLETE',files.sort().join(','));})();",
            root.path(), &["fs_read"], lane,
        ).expect("native generator drains all matching paths");
        assert_eq!(lines, ["GLOB_COMPLETE tree/a.txt,tree/sub/b.txt"]);
    }
}

#[test]
fn glob_invalid_queries_fail_before_io_and_no_match_does_not_grant_authority() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().unwrap();
        fixture(root.path());
        let (lines, effects) = run(
            "const fs=require('fs');try{fs.globSync('../*');}catch(e){console.log(e.code);}\
             try{fs.globSync(new Array(129).fill('*'));}catch(e){console.log(e.code);}",
            root.path(), &[], lane,
        ).expect("query validation requires no filesystem authority");
        assert_eq!(lines, ["ERR_FS_GLOB_UNSUPPORTED", "ERR_FS_GLOB_LIMIT"]);
        assert!(effects.is_empty());
        let refused = run("require('fs').globSync('missing/**/*.txt');", root.path(), &["fs_write"], lane)
            .expect_err("even no-match discovery requires explicit read authority");
        assert!(refused.to_ascii_lowercase().contains("capabil"), "{refused}");
    }
}
