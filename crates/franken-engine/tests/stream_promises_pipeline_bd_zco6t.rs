//! End-to-end proof for compat corpus fixture 0045
//! (`stream_ext/0045_stream_promises_pipeline.js`) on the orchestrated
//! product path (bd-zco6t).
//!
//! The engine already pins this shape at the `HybridRouter::eval` level
//! (stream_builtin_bd_m8vaa `tc::stream::0045`), but the corpus runs through
//! the product stack — and bd-sxh8o.1 proved HybridRouter green does not
//! imply the orchestrated path is green. These tests execute the fixture
//! VERBATIM through `ExecutionOrchestrator::execute` under the product
//! capability gate: CJS destructured `require('stream')`, a
//! constructor-option `Writable` sink, `Readable.from` pumping on the
//! deterministic I/O lane, `promises.pipeline` awaited inside an async IIFE,
//! and the event loop draining the whole pipeline to idle before the run
//! report finalizes.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, LabFixtureExecutionOrchestratorExt,
    OrchestratorConfig, OrchestratorResult,
};

fn run_fixture(name: &str, source: &str) -> OrchestratorResult {
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    let package = ExtensionPackage {
        extension_id: format!("{name}-e2e"),
        source: source.to_string(),
        source_file: None,
        module_root: None,
        capabilities: vec![
            "vm_dispatch".to_string(),
            "heap_allocate".to_string(),
            "console".to_string(),
            "timer".to_string(),
        ],
        version: "1.0.0".to_string(),
        metadata: BTreeMap::new(),
    };
    orchestrator
        .execute(&package)
        .expect("corpus fixture source must execute through the product stack")
}

fn console_messages(result: &OrchestratorResult) -> Vec<&str> {
    result
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect()
}

/// Corpus fixture 0045 (verbatim): the awaited promise pipeline delivers both
/// chunks through the constructor-option Writable and resolves, so the async
/// IIFE's final log runs before the loop goes idle.
#[test]
fn fixture_0045_stream_promises_pipeline_bd_zco6t() {
    let result = run_fixture(
        "fe_zco6t_0045",
        "const {promises, Readable, Writable} = require('stream');\n\
         (async () => {\n\
           const out = [];\n\
           const w = new Writable({write(c, e, cb) { out.push(c.toString()); cb(); }});\n\
           await promises.pipeline(Readable.from(['pp1', 'pp2']), w);\n\
           console.log('done:' + out.join(','));\n\
         })();\n",
    );
    assert_eq!(
        console_messages(&result),
        vec!["done:pp1,pp2"],
        "Node reference output: pipeline resolves after both writes, in order"
    );
}

/// Ordering probe on the same orchestrated surface: writes happen in chunk
/// order, the sink finishes before the awaited pipeline resolves, and
/// top-level synchronous output precedes all of it. Pins that the awaited
/// pipeline neither resolves early (before sink finish) nor reorders chunks
/// under the product event loop.
#[test]
fn fixture_0045_pipeline_resolution_ordering_bd_zco6t() {
    let result = run_fixture(
        "fe_zco6t_0045_order",
        "const {promises, Readable, Writable} = require('stream');\n\
         const events = [];\n\
         const w = new Writable({write(c, e, cb) { events.push('write:' + c.toString()); cb(); }});\n\
         w.on('finish', () => events.push('finish'));\n\
         (async () => {\n\
           await promises.pipeline(Readable.from(['a', 'b']), w);\n\
           events.push('resolved');\n\
           console.log(events.join(','));\n\
         })();\n\
         console.log('sync');\n",
    );
    assert_eq!(
        console_messages(&result),
        vec!["sync", "write:a,write:b,finish,resolved"],
        "sync output first; then chunk-ordered writes, sink finish, and only \
         then the awaited pipeline resolution"
    );
}
