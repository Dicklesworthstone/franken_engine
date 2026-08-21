//! End-to-end proof for compat corpus fixture 0044
//! (`stream_ext/0044_stream_writable_destroy.js`) on the orchestrated
//! product path (bd-zco6t).
//!
//! `Writable.destroy()` tears the stream down without completing it: the
//! `destroyed` flag flips synchronously, the `close` event is delivered
//! asynchronously afterwards, and `finish` must NEVER fire (finish is the
//! graceful `end()` completion signal, which destroy bypasses). The tests
//! execute the fixture VERBATIM through `ExecutionOrchestrator::execute`
//! under the product capability gate — the corpus's path, not
//! HybridRouter-only.

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

/// Corpus fixture 0044 (verbatim): destroy flips `destroyed` synchronously
/// (so it prints before any event), `close` is delivered asynchronously
/// afterwards, and the registered `finish` listener never fires.
#[test]
fn fixture_0044_writable_destroy_closes_without_finish_bd_zco6t() {
    let result = run_fixture(
        "fe_zco6t_0044",
        "const {Writable} = require('stream');\n\
         const w = new Writable({write(c, e, cb) { cb(); }});\n\
         w.on('finish', () => console.log('finish-should-not-fire'));\n\
         w.on('close', () => console.log('close'));\n\
         w.write('a');\n\
         w.destroy();\n\
         console.log('destroyed:' + w.destroyed);\n",
    );
    let messages = console_messages(&result);
    assert_eq!(
        messages,
        vec!["destroyed:true", "close"],
        "Node reference output: synchronous destroyed flag first, async close \
         second, and finish suppressed entirely"
    );
    assert!(
        !messages.contains(&"finish-should-not-fire"),
        "destroy must bypass the graceful finish signal: {messages:?}"
    );
}

/// Idempotence probe on the same orchestrated surface: a second `destroy()`
/// is a no-op — `close` is delivered exactly once and `destroyed` stays true
/// both times it is observed.
#[test]
fn fixture_0044_destroy_is_idempotent_bd_zco6t() {
    let result = run_fixture(
        "fe_zco6t_0044_idempotent",
        "const {Writable} = require('stream');\n\
         const w = new Writable({write(c, e, cb) { cb(); }});\n\
         let closes = 0;\n\
         w.on('close', () => { closes += 1; console.log('close:' + closes); });\n\
         w.destroy();\n\
         w.destroy();\n\
         console.log('destroyed:' + w.destroyed);\n\
         Promise.resolve().then(() => console.log('after:' + w.destroyed));\n",
    );
    let messages = console_messages(&result);
    assert_eq!(
        messages.first().copied(),
        Some("destroyed:true"),
        "double destroy still reports destroyed synchronously: {messages:?}"
    );
    assert_eq!(
        messages
            .iter()
            .filter(|message| message.starts_with("close:"))
            .collect::<Vec<_>>(),
        vec![&"close:1"],
        "close must be delivered exactly once for a doubly-destroyed stream: {messages:?}"
    );
    assert!(
        messages.contains(&"after:true"),
        "the destroyed flag stays true across later microtasks: {messages:?}"
    );
}
