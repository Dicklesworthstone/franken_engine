//! Promise pathname writes must use the same bounded, recorded descriptor path
//! for scalars and iterables. Host-JavaScript checks do not establish this.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use frankenengine_engine::baseline_interpreter::LaneChoice;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, LabFixtureExecutionOrchestratorExt, OrchestratorConfig,
};
use frankenengine_extension_host::host_io::{
    FsOperation, HostIoOutcome, HostIoRecorder, HostIoRequest, InMemoryHostIoTranscript,
    SandboxedHostIo,
};

type Run = (Vec<String>, Vec<(HostIoRequest, HostIoOutcome)>);

fn run(source: &str, root: &Path, lane: LaneChoice, caps: &[&str]) -> Result<Run, String> {
    let provider = Arc::new(SandboxedHostIo::with_root(root).expect("sandbox"));
    let recording = Arc::new(InMemoryHostIoTranscript::recording());
    let recorder: Arc<dyn HostIoRecorder> = recording.clone();
    let mut runtime = ExecutionOrchestrator::new(OrchestratorConfig {
        force_lane: Some(lane),
        ..OrchestratorConfig::default()
    });
    runtime.set_host_io(provider, Some(recorder));
    let mut capabilities = vec!["vm_dispatch", "heap_allocate", "builtin", "console"];
    capabilities.extend_from_slice(caps);
    let package = ExtensionPackage {
        extension_id: "promise-file-contents".into(),
        source: source.into(),
        source_file: None,
        module_root: None,
        capabilities: capabilities.into_iter().map(str::to_string).collect(),
        version: "1.0.0".into(),
        metadata: BTreeMap::new(),
    };
    let result = runtime.execute(&package).map_err(|error| format!("{error:?}"))?;
    Ok((result.console_output.into_iter().map(|line| line.message).collect(), recording.entries()))
}

#[test]
fn scalar_and_iterable_writes_share_recorded_flush_before_close() {
    let source = r#"
const fs=require('node:fs/promises');
(async function(){
  await fs.writeFile('data','abc',{flush:true});
  await fs.appendFile('data',Buffer.from('!'),{flush:true});
  await fs.appendFile('data',['é'],{flush:true});
  console.log('WRITE_CONTENTS_COMPLETE');
})();
"#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().unwrap();
        let (lines, effects) = run(source, root.path(), lane, &["fs_write"]).unwrap();
        assert_eq!(lines, ["WRITE_CONTENTS_COMPLETE"]);
        assert_eq!(std::fs::read(root.path().join("data")).unwrap(), "abc!é".as_bytes());
        let operations: Vec<&str> = effects.iter().filter_map(|(request, _)| match request {
            HostIoRequest::FsMeta { operation, .. } => Some(operation.as_str()),
            _ => None,
        }).collect();
        assert_eq!(operations, [
            "open", "write_fd", "fsync", "close_fd",
            "open", "write_fd", "fsync", "close_fd",
            "open", "write_fd", "fsync", "close_fd",
        ]);
    }
}

#[test]
fn large_scalar_writes_are_bounded_without_changing_the_output() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().unwrap();
        let (lines, effects) = run(
            "require('fs/promises').writeFile('data',Buffer.alloc(40007,90),{flush:true})\
             .then(()=>console.log('BOUNDED_WRITE_COMPLETE'));",
            root.path(), lane, &["fs_write"],
        ).unwrap();
        assert_eq!(lines, ["BOUNDED_WRITE_COMPLETE"]);
        assert_eq!(std::fs::read(root.path().join("data")).unwrap(), vec![90; 40007]);
        let mut sizes = Vec::new();
        for (request, _) in &effects {
            if let HostIoRequest::FsMeta { operation: FsOperation::WriteFd, data, .. } = request {
                assert!(!data.is_empty() && data.len() <= 16384);
                sizes.push(data.len());
            }
        }
        assert_eq!(sizes.iter().sum::<usize>(), 40007);
        assert!(sizes.len() >= 3);
    }
}

#[test]
fn scalar_preflight_failure_never_truncates_or_opens() {
    let source = r#"
const fs=require('fs/promises');
(async function(){
  try{await fs.writeFile('data','wrong',{flush:'yes'});}catch(e){console.log(e.code);}
  const control=new AbortController();control.abort(false);
  try{await fs.writeFile('data','wrong',{flush:true,signal:control.signal});}
  catch(e){console.log(e.name,e.code,e.cause===false);}
  console.log('PREFLIGHT_COMPLETE');
})();
"#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("data"), b"keep").unwrap();
        let (lines, effects) = run(source, root.path(), lane, &["fs_write"]).unwrap();
        assert_eq!(lines, ["ERR_INVALID_ARG_TYPE", "AbortError ABORT_ERR true", "PREFLIGHT_COMPLETE"]);
        assert!(!effects.iter().any(|(request, _)| matches!(request, HostIoRequest::FsMeta { .. })));
        assert_eq!(std::fs::read(root.path().join("data")).unwrap(), b"keep");
    }
}

#[test]
fn scalar_path_does_not_gain_write_authority_from_a_read_grant() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().unwrap();
        let error = run(
            "require('fs/promises').writeFile('forbidden','x',{flush:true});",
            root.path(), lane, &["fs_read"],
        ).expect_err("the protected write effect requires FsWrite");
        assert!(error.to_ascii_lowercase().contains("capabil"), "{error}");
        assert!(!root.path().join("forbidden").exists());
    }
}
