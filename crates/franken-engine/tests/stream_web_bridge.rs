//! Execute the bridge through the actual engine. Host-adapter tests do not
//! establish that the native parser, module identity, GC or VM passes these.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use frankenengine_engine::baseline_interpreter::LaneChoice;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, LabFixtureExecutionOrchestratorExt, OrchestratorConfig,
};

fn run(source: &str, lane: LaneChoice) -> Vec<String> {
    let mut engine = ExecutionOrchestrator::new(OrchestratorConfig {
        force_lane: Some(lane), ..OrchestratorConfig::default()
    });
    let package = ExtensionPackage {
        extension_id: "stream-web-bridge".into(), source: source.into(),
        source_file: None, module_root: None,
        capabilities: ["vm_dispatch", "heap_allocate", "builtin", "console"]
            .into_iter().map(str::to_string).collect(),
        version: "1.0.0".into(), metadata: BTreeMap::new(),
    };
    engine.execute(&package).expect("native bridge completes")
        .console_output.into_iter().map(|line| line.message).collect()
}

#[test]
fn node_and_explicit_web_modules_share_stream_endpoints_without_io_authority() {
    let source = r#"
const s=require('node:stream'), w=require('node:stream/web');
const Object='guest', Promise='guest', Reflect='guest', Uint8Array='guest';
const values=[];
const destination=new s.Writable({objectMode:true,write(value,encoding,done){values.push(value);done();}});
const transformed=s.Readable.toWeb(s.Readable.from([1,2,3]))
  .pipeThrough(new w.TransformStream({transform(value,c){c.enqueue(value*2);}}));
s.promises.pipeline(s.Readable.fromWeb(transformed,{objectMode:true}),
  s.Writable.fromWeb(s.Writable.toWeb(destination),{objectMode:true}))
  .then(()=>console.log('BRIDGE_COMPLETE',values.join(','),destination.writableFinished));
"#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(run(source, lane), ["BRIDGE_COMPLETE 2,4,6 true"]);
    }
}

#[test]
fn a_node_only_import_can_lazily_load_the_canonical_web_dependency() {
    let source = r#"
const s=require('stream'), values=[];
const destination=new s.Writable({objectMode:true,write(value,encoding,done){values.push(value);done();}});
s.Readable.toWeb(s.Readable.from(['a','b'])).pipeTo(s.Writable.toWeb(destination))
  .then(()=>console.log('LAZY_BRIDGE_COMPLETE',values.join(','),destination.writableFinished));
"#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(run(source, lane), ["LAZY_BRIDGE_COMPLETE a,b true"]);
    }
}

#[test]
fn abort_unblocks_an_active_node_write_and_cleans_up_once() {
    let source = r#"
const s=require('node:stream'), events=[];
const destination=new s.Writable({write(value,encoding,done){events.push('write');},
  destroy(reason,done){events.push('destroy');done(reason);}});
const writer=s.Writable.toWeb(destination).getWriter(), reason=Error('stop');
const pending=writer.write('a').then(()=>false,error=>error===reason);
setImmediate(function(){writer.abort(reason).then(async function(){
  console.log('BRIDGE_ABORT_COMPLETE',await pending,events.join(','),destination.destroyed);
});});
"#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(run(source, lane), ["BRIDGE_ABORT_COMPLETE true write,destroy true"]);
    }
}

#[test]
fn streamed_bytes_keep_view_offsets_and_do_not_reclassify_rejection_as_eof() {
    let source = r#"
const s=require('stream'),w=require('stream/web');
const source=new w.ReadableStream({start(c){c.enqueue(new Uint8Array([9,65,66,8]).subarray(1,3));c.close();}});
const chunks=[];s.Readable.fromWeb(source).on('data',chunk=>chunks.push(chunk.toString('hex')))
 .on('end',function(){console.log('BRIDGE_BYTES_COMPLETE',chunks.join(','),source.locked);});
const bad=s.Readable.fromWeb(new w.ReadableStream({start(c){c.error(false);}}));
bad.on('error',error=>console.log('BRIDGE_FALSE_ERROR',error.code,error.cause===false));
"#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        // Independent endpoint completion can interleave; neither may vanish.
        let mut lines = run(source, lane);
        lines.sort();
        assert_eq!(lines, ["BRIDGE_BYTES_COMPLETE 4142 true", "BRIDGE_FALSE_ERROR ERR_STREAM_WEB true"]);
    }
}
