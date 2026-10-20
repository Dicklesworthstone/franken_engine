//! Binary files and Blob byte streams through the native shared runtime.
//! Host-only JavaScript checks do not establish that these Rust tests pass.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::LaneChoice;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, LabFixtureExecutionOrchestratorExt, OrchestratorConfig,
};

fn run(source: &str, goal: ParseGoal, lane: LaneChoice) -> Vec<String> {
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig {
        force_lane: Some(lane),
        parse_goal: goal,
        ..OrchestratorConfig::default()
    });
    let package = ExtensionPackage {
        extension_id: "binary-files".into(),
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
        .expect("binary files complete without filesystem or network authority")
        .console_output
        .into_iter()
        .map(|entry| entry.message)
        .collect()
}

#[test]
fn files_retain_native_blob_storage_and_module_identity() {
    let source = r#"
const {File, Blob}=require('buffer');
const again=require('node:buffer');
const bytes=new Uint8Array([99,65,66,88]);
const f=new File([new DataView(bytes.buffer,1,2),{toString(){return '!';}}],
  'resume.txt',{type:'TEXT/PLAIN',lastModified:7});
bytes.fill(90);
(async function(){
 console.log(f.name,f.type,f.size,f.lastModified,f instanceof File,f instanceof Blob,again.File===File);
 console.log(await f.text(), f.slice(0,1) instanceof File);
 const copy=await f.bytes();copy[0]=90;console.log(await f.text());
 console.log(Object.prototype.toString.call(f));
})();
"#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(run(source, ParseGoal::Script, lane), [
            "resume.txt text/plain 3 7 true true true", "AB! false", "AB!", "[object File]",
        ]);
    }
}

#[test]
fn esm_files_use_the_same_byte_stream_constructor_and_byob_eof() {
    let source = r#"
import {File as BinaryFile, Blob} from 'node:buffer';
import {ReadableStream} from 'node:stream/web';
const WeakMap='guest', Date='guest', Symbol='guest', process='guest';
const file=new BinaryFile(['abcde'],'data.bin',{lastModified:0});
const stream=file.stream();console.log(stream instanceof ReadableStream,file instanceof Blob);
const reader=stream.getReader({mode:'byob'});
const first=await reader.read(new Uint8Array(2));
const last=await reader.read(new Uint8Array(8),{min:8});
console.log(first.done,Array.from(first.value).join(','),last.done,Array.from(last.value).join(','));
const end=await reader.read(new Uint8Array(2));console.log(end.done,end.value.byteLength);
"#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(run(source, ParseGoal::Module, lane), [
            "true true", "false 97,98 true 99,100,101", "true 0",
        ]);
    }
}

#[test]
fn streamed_files_keep_immutable_bytes_and_cancel_without_late_output() {
    // The 64 KiB first chunk is our bounded-copy contract, not Node's chunk
    // segmentation (the reference may deliver all 65539 bytes in one chunk).
    let source = r#"
const {File,Blob}=require('buffer');
const f=new File([new Uint8Array(65539).fill(37)],'large',{lastModified:0});
Object.defineProperty(f,'size',{get(){throw Error('public size');}});
f.slice=()=>{throw Error('public slice');};f.arrayBuffer=()=>{throw Error('public read');};
(async function(){
 const reader=f.stream().getReader();const first=await reader.read();
 console.log(first.value.byteLength,first.value[0]);await reader.cancel('stop');
 console.log((await reader.read()).done,(await f.bytes())[0]);
 const empty=new Blob().stream().getReader({mode:'byob'});
 const end=await empty.read(new Uint8Array(4));console.log(end.done,end.value.byteLength);
})();
"#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(run(source, ParseGoal::Script, lane), ["65536 37", "true 37", "true 0"]);
    }
}

#[test]
fn file_conversions_complete_once_in_reference_order() {
    let source = r#"
const {File}=require('buffer');const seen=[];
const parts={get [Symbol.iterator](){seen.push('iterator');return function*(){
 seen.push('start');yield {toString(){seen.push('part');return 'data';}};seen.push('end');};}};
const f=new File(parts,{toString(){seen.push('name');return 'x';}},{
 get type(){seen.push('type');return {toString(){seen.push('mime');return 'TEXT/PLAIN';}};},
 get endings(){seen.push('endings');return 'transparent';},
 get lastModified(){seen.push('time');return 2;}
});
console.log(seen.join(','));console.log(f.name,f.type,f.size,f.lastModified);
try{Object.getOwnPropertyDescriptor(File.prototype,'name').get.call({});}
catch(error){console.log(error.name);}
"#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(run(source, ParseGoal::Script, lane), [
            "iterator,type,endings,iterator,start,part,end,mime,time,name",
            "x text/plain 4 2", "TypeError",
        ]);
    }
}
