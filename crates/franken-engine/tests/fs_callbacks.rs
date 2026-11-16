//! Callback filesystem APIs must execute through the native, sandboxed host.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use frankenengine_engine::baseline_interpreter::LaneChoice;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, LabFixtureExecutionOrchestratorExt, OrchestratorConfig,
};
use frankenengine_extension_host::host_io::{
    HostIoRecorder, InMemoryHostIoTranscript, SandboxedHostIo,
};

fn run(source: &str, root: &Path, lane: LaneChoice, caps: &[&str]) -> Result<Vec<String>, String> {
    let provider = Arc::new(SandboxedHostIo::with_root(root).expect("sandbox provider"));
    let recorder: Arc<dyn HostIoRecorder> = Arc::new(InMemoryHostIoTranscript::recording());
    let mut runtime = ExecutionOrchestrator::new(OrchestratorConfig {
        force_lane: Some(lane),
        ..OrchestratorConfig::default()
    });
    runtime.set_host_io(provider, Some(recorder));
    let mut capabilities = vec!["vm_dispatch", "heap_allocate", "builtin", "console"];
    capabilities.extend_from_slice(caps);
    let package = ExtensionPackage {
        extension_id: "fs-callback-integration".into(),
        source: source.into(),
        source_file: None,
        module_root: None,
        capabilities: capabilities.into_iter().map(str::to_string).collect(),
        version: "1.0.0".into(),
        metadata: BTreeMap::new(),
    };
    let result = runtime
        .execute(&package)
        .map_err(|error| format!("{error:?}"))?;
    Ok(result
        .console_output
        .into_iter()
        .map(|line| line.message)
        .collect())
}

#[test]
fn callbacks_complete_descriptor_transfer_without_synchronous_completion() {
    let source = r#"
const fs=require('node:fs');const queueMicrotask='guest',URL='guest',DataView='guest';
let returned=false;
fs.open('result.txt','w+',function(error,fd){
  if(error)throw error;console.log('OPEN_CALLBACK',returned,typeof fd);
  const buffer=Buffer.from('_hello_');
  fs.write(fd,buffer,1,5,0,function(error,n,original){
    if(error)throw error;console.log('WRITE_CALLBACK',n,original===buffer);
    const output=Buffer.alloc(7,95);
    fs.read(fd,output,{offset:1,length:5,position:0},function(error,n,original){
      if(error)throw error;console.log('READ_CALLBACK',n,original===output,output.toString());
      fs.fsync(fd,function(error){if(error)throw error;
        fs.close(fd,function(error){if(error)throw error;console.log('FD_COMPLETE');});
      });
    });
  });
});
returned=true;
"#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().expect("sandbox");
        let output = run(source, root.path(), lane, &["fs_read", "fs_write"])
            .expect("native descriptor callbacks complete");
        assert_eq!(
            output,
            [
                "OPEN_CALLBACK true number",
                "WRITE_CALLBACK 5 true",
                "READ_CALLBACK 5 true _hello_",
                "FD_COMPLETE",
            ]
        );
        assert_eq!(
            std::fs::read(root.path().join("result.txt")).unwrap(),
            b"hello"
        );
    }
}

#[test]
fn promisified_callbacks_return_original_buffers_and_exact_byte_counts() {
    let source = r#"
const fs=require('fs');const {promisify}=require('util');
(async function(){
  const fd=await promisify(fs.open)('vector.txt','w+');
  const input=[Buffer.from('ab'),Buffer.from('cd')];
  const written=await promisify(fs.writev)(fd,input,0);
  const output=[Buffer.alloc(1),Buffer.alloc(5,95)];
  const read=await promisify(fs.readv)(fd,output,0);
  console.log('VECTOR_CALLBACKS',written.bytesWritten,written.buffer===input,
    read.bytesRead,read.buffers===output,Buffer.concat(output).toString());
  await promisify(fs.close)(fd);console.log('VECTOR_COMPLETE');
})();
"#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().expect("sandbox");
        assert_eq!(
            run(source, root.path(), lane, &["fs_read", "fs_write"]).unwrap(),
            ["VECTOR_CALLBACKS 4 true 4 true abcd__", "VECTOR_COMPLETE",]
        );
        assert_eq!(
            std::fs::read(root.path().join("vector.txt")).unwrap(),
            b"abcd"
        );
    }
}

#[test]
fn metadata_and_copy_callbacks_share_the_same_admitted_filesystem() {
    let source = r#"
const fs=require('fs');const {promisify}=require('util');
(async function(){
  const names=await promisify(fs.readdir)('input');
  const first=await promisify(fs.stat)('input/'+names[0]);
  if(!first.isFile())throw Error('wrong stat');
  await promisify(fs.cp)('input','output',{recursive:true,async filter(source){
    await Promise.resolve();return !source.endsWith('skip.txt');
  }});
  await promisify(fs.rename)('output/keep.txt','output/result.txt');
  console.log('METADATA_COMPLETE',first.size,fs.readFileSync('output/result.txt','utf8'),
    fs.existsSync('output/skip.txt'));
})();
"#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().expect("sandbox");
        std::fs::create_dir(root.path().join("input")).unwrap();
        std::fs::write(root.path().join("input/keep.txt"), b"data").unwrap();
        std::fs::write(root.path().join("input/skip.txt"), b"also").unwrap();
        assert_eq!(
            run(source, root.path(), lane, &["fs_read", "fs_write"]).unwrap(),
            ["METADATA_COMPLETE 4 data false"]
        );
        assert_eq!(
            std::fs::read(root.path().join("output/result.txt")).unwrap(),
            b"data"
        );
        assert!(!root.path().join("output/skip.txt").exists());
    }
}

#[test]
fn callback_loading_does_not_authorize_file_writes() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().expect("sandbox");
        let error = run(
            "require('fs').open('forbidden.txt','w',function(error,fd){console.log('UNEXPECTED');});",
            root.path(), lane, &["fs_read"],
        ).expect_err("the queued callback must retain FsWrite admission");
        assert!(error.to_ascii_lowercase().contains("capabil"), "{error}");
        assert!(!root.path().join("forbidden.txt").exists());
    }
}

#[test]
fn invalid_callbacks_do_not_open_or_truncate_a_path() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().expect("sandbox");
        std::fs::write(root.path().join("keep.txt"), b"original").unwrap();
        let source = r#"
const fs=require('fs');
try{fs.open('keep.txt','w',null);}catch(error){console.log('INVALID_CALLBACK',error.code);}
console.log('VALIDATION_COMPLETE',fs.readFileSync('keep.txt','utf8'));
"#;
        assert_eq!(
            run(source, root.path(), lane, &["fs_read", "fs_write"]).unwrap(),
            [
                "INVALID_CALLBACK ERR_INVALID_ARG_TYPE",
                "VALIDATION_COMPLETE original",
            ]
        );
        assert_eq!(
            std::fs::read(root.path().join("keep.txt")).unwrap(),
            b"original"
        );
    }
}

#[test]
fn copy_file_masks_preserve_existing_files_across_sync_callback_and_promise_apis() {
    let source = r#"
const fs=require('fs');
(async function(){
  console.log('COPY_FLAGS',fs.constants.COPYFILE_EXCL,fs.constants.COPYFILE_FICLONE,
    fs.constants.COPYFILE_FICLONE_FORCE,fs.promises.constants===fs.constants);
  fs.copyFileSync('source','sync-created',fs.constants.COPYFILE_EXCL);
  try{fs.copyFileSync('source','keep',fs.constants.COPYFILE_EXCL);}
  catch(error){console.log('COPY_SYNC_REFUSED',error.code);}
  let returned=false;
  await new Promise(function(resolve){
    fs.copyFile('source','keep',fs.constants.COPYFILE_EXCL|fs.constants.COPYFILE_FICLONE,
      function(error){console.log('COPY_CALLBACK_REFUSED',returned,error.code);resolve();});
    returned=true;
  });
  try{await fs.promises.copyFile('source','keep',1.9);}
  catch(error){console.log('COPY_PROMISE_REFUSED',error.code);}
  await fs.promises.copyFile('source','promise-created',3);
  console.log('COPY_PRESERVED',fs.readFileSync('keep','utf8'));
  fs.copyFileSync('source','fractional-default',-0.9);
  fs.copyFileSync('source','fallback',2);
  console.log('COPY_CREATED',fs.readFileSync('sync-created','utf8'),
    fs.readFileSync('promise-created','utf8'),fs.readFileSync('fallback','utf8'));
})();
"#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().expect("sandbox");
        std::fs::write(root.path().join("source"), b"copied").unwrap();
        std::fs::write(root.path().join("keep"), b"preserved").unwrap();
        std::fs::write(root.path().join("fallback"), b"previous contents").unwrap();
        assert_eq!(
            run(source, root.path(), lane, &["fs_read", "fs_write"]).unwrap(),
            [
                "COPY_FLAGS 1 2 4 true",
                "COPY_SYNC_REFUSED EEXIST",
                "COPY_CALLBACK_REFUSED true EEXIST",
                "COPY_PROMISE_REFUSED EEXIST",
                "COPY_PRESERVED preserved",
                "COPY_CREATED copied copied copied",
            ]
        );
        assert_eq!(
            std::fs::read(root.path().join("keep")).unwrap(),
            b"preserved"
        );
        for name in [
            "sync-created",
            "promise-created",
            "fractional-default",
            "fallback",
        ] {
            assert_eq!(std::fs::read(root.path().join(name)).unwrap(), b"copied");
        }
    }
}

#[test]
fn copy_file_invalid_modes_and_forced_clone_do_not_mutate_files() {
    let source = r#"
const fs=require('fs');
let callbacks=0;
try{fs.copyFile('source','keep','1',function(){callbacks++;});}
catch(error){console.log('COPY_TYPE',error.code);}
try{fs.copyFileSync('source','keep',8);}
catch(error){console.log('COPY_RANGE',error.code);}
for(const mode of [4,5,6,7.9]){
  try{fs.copyFileSync('source','must-not-exist',mode);}
  catch(error){console.log('COPY_CLONE',error.code);}
}
console.log('COPY_UNCHANGED',callbacks,fs.readFileSync('keep','utf8'),
  fs.existsSync('must-not-exist'));
"#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().expect("sandbox");
        std::fs::write(root.path().join("source"), b"copied").unwrap();
        std::fs::write(root.path().join("keep"), b"preserved").unwrap();
        assert_eq!(
            run(source, root.path(), lane, &["fs_read", "fs_write"]).unwrap(),
            [
                "COPY_TYPE ERR_INVALID_ARG_TYPE",
                "COPY_RANGE ERR_OUT_OF_RANGE",
                "COPY_CLONE ENOTSUP",
                "COPY_CLONE ENOTSUP",
                "COPY_CLONE ENOTSUP",
                "COPY_CLONE ENOTSUP",
                "COPY_UNCHANGED 0 preserved false",
            ]
        );
        assert_eq!(
            std::fs::read(root.path().join("keep")).unwrap(),
            b"preserved"
        );
        assert!(!root.path().join("must-not-exist").exists());
    }
}

#[test]
fn copy_file_flags_do_not_grant_write_authority() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().expect("sandbox");
        std::fs::write(root.path().join("source"), b"source").unwrap();
        let error = run(
            "require('fs').copyFileSync('source','forbidden',1);",
            root.path(),
            lane,
            &["fs_read"],
        )
        .expect_err("exclusive creation still requires FsWrite");
        assert!(error.to_ascii_lowercase().contains("capabil"), "{error}");
        assert!(!root.path().join("forbidden").exists());
    }
}
