//! Recursive copying through the real sandboxed engine on both native lanes.
//! Reference-host JS tests do not establish that these Rust tests pass.
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
        extension_id: "filesystem-copy".into(),
        source: source.into(),
        source_file: None,
        module_root: None,
        capabilities: capabilities.into_iter().map(str::to_string).collect(),
        version: "1.0.0".into(),
        metadata: BTreeMap::new(),
    };
    let output = orchestrator.execute(&package).map_err(|e| format!("{e:?}"))?;
    Ok((output.console_output.into_iter().map(|entry| entry.message).collect(), recording.entries()))
}

#[test]
fn commonjs_copy_uses_bounded_native_descriptor_effects_and_preserves_bytes() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("src/deep")).unwrap();
        let bytes: Vec<u8> = (0..40007).map(|i| (i % 251) as u8).collect();
        std::fs::write(root.path().join("src/deep/data.bin"), &bytes).unwrap();
        let (lines, effects) = run(
            "const fs = require('node:fs'); fs.cpSync('src', 'dst', {recursive:true}); console.log('COPY_COMPLETE');",
            root.path(), &["fs_read", "fs_write"], lane, ParseGoal::Script,
        ).expect("native copy completes");
        assert_eq!(lines, ["COPY_COMPLETE"]);
        assert_eq!(std::fs::read(root.path().join("dst/deep/data.bin")).unwrap(), bytes);
        assert_eq!(std::fs::read(root.path().join("src/deep/data.bin")).unwrap(), bytes);
        let mut reads = 0;
        let mut writes = 0;
        let mut opens = 0;
        let mut closes = 0;
        for (request, _) in effects {
            if let HostIoRequest::FsMeta { operation, arguments, data, .. } = request {
                match operation {
                    FsOperation::ReadFd => {
                        reads += 1;
                        let length = arguments.iter().find_map(|a| a.strip_prefix("length=")).unwrap();
                        assert!(length.parse::<usize>().unwrap() <= 16384);
                    }
                    FsOperation::WriteFd => { writes += 1; assert!(data.len() <= 16384); }
                    FsOperation::Open => opens += 1,
                    FsOperation::CloseFd => closes += 1,
                    FsOperation::CopyFile => panic!("must not delegate a whole unbounded file copy"),
                    _ => {}
                }
            }
        }
        assert!(reads >= 4 && writes >= 3);
        assert_eq!(opens, 2);
        assert_eq!(closes, opens);
    }
}

#[test]
fn promise_copy_awaits_filters_and_does_not_visit_excluded_subtrees() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("src/skip")).unwrap();
        std::fs::write(root.path().join("src/keep"), b"kept").unwrap();
        std::fs::write(root.path().join("src/skip/hidden"), b"excluded").unwrap();
        let (lines, _) = run(
            "const { cp } = require('node:fs/promises'); const Object='guest'; const String='guest'; \
             cp('src','dst',{recursive:true,filter:async function(src){await Promise.resolve();return !src.endsWith('/skip');}})\
             .then(()=>console.log('FILTERED_COPY_COMPLETE'));",
            root.path(), &["fs_read", "fs_write"], lane, ParseGoal::Script,
        ).expect("promise and protected module globals");
        assert_eq!(lines, ["FILTERED_COPY_COMPLETE"]);
        assert_eq!(std::fs::read(root.path().join("dst/keep")).unwrap(), b"kept");
        assert!(!root.path().join("dst/skip").exists());
    }
}

#[test]
fn self_copy_conflicts_and_unsupported_metadata_never_report_completion() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("src")).unwrap();
        std::fs::write(root.path().join("src/file"), b"retained").unwrap();
        let (lines, _) = run(
            "const fs=require('fs'); try{fs.cpSync('src','src/out',{recursive:true});}catch(e){console.log(e.code);}\
             try{fs.cpSync('src/file','other',{preserveTimestamps:true});}catch(e){console.log(e.code);}",
            root.path(), &["fs_read", "fs_write"], lane, ParseGoal::Script,
        ).expect("explicit unsupported operations");
        assert_eq!(lines, ["ERR_FS_CP_EINVAL", "ERR_FS_CP_UNSUPPORTED"]);
        assert!(!root.path().join("src/out").exists());
        assert!(!root.path().join("other").exists());
        assert_eq!(std::fs::read(root.path().join("src/file")).unwrap(), b"retained");
    }
}

#[test]
fn neither_read_nor_write_authority_can_be_inferred_from_the_other() {
    for caps in [&["fs_read"][..], &["fs_write"][..]] {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("source"), b"private").unwrap();
        let result = run("require('fs').cpSync('source','destination');", root.path(), caps, LaneChoice::QuickJs, ParseGoal::Script);
        let error = result.expect_err("both capability classes remain required");
        assert!(error.to_ascii_lowercase().contains("capabil"), "{error}");
        assert!(!root.path().join("destination").exists());
    }
}
