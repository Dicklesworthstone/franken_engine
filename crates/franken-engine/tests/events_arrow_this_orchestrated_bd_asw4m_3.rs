//! bd-asw4m.3 — events fixture-0022 semantics on the ORCHESTRATED product
//! path (`ExecutionOrchestrator::execute`), not the HybridRouter-only eval
//! harness: an ordinary function listener is invoked with `this = emitter`,
//! while an arrow listener installed from inside a method keeps that method's
//! lexical `this`.
//!
//! The HybridRouter twin lives in `tests/arrow_lexical_this_bd_asw4m_3.rs`;
//! this suite pins that the same semantics survive the full orchestrated
//! pipeline (capability admission, IFC annotation, adaptive routing, and the
//! evidence-emitting execution cell), with no EventEmitter source-pattern
//! heuristics anywhere in the chain.

use std::collections::BTreeMap;

use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, LabFixtureExecutionOrchestratorExt,
};

fn package(id: &str, source: &str) -> ExtensionPackage {
    ExtensionPackage {
        extension_id: id.to_string(),
        source: source.to_string(),
        source_file: None,
        module_root: None,
        capabilities: vec![],
        version: "1.0.0".to_string(),
        metadata: BTreeMap::new(),
    }
}

fn console_lines(id: &str, source: &str) -> Vec<String> {
    let mut orchestrator = ExecutionOrchestrator::with_defaults();
    let result = orchestrator
        .execute(&package(id, source))
        .unwrap_or_else(|error| panic!("orchestrated execute failed for {id}: {error}"));
    result
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect()
}

/// Fixture-0022 core: the ordinary listener observes the emitter as `this`.
#[test]
fn orchestrated_ordinary_listener_binds_the_emitter() {
    let lines = console_lines(
        "ext-asw4m3-ordinary",
        r#"
        const { EventEmitter } = require('events');
        const e = new EventEmitter();
        e.on('a', function () { console.log('fn:' + (this === e)); });
        e.emit('a');
        "#,
    );
    assert_eq!(lines, vec!["fn:true".to_string()]);
}

/// Fixture-0022 core: an arrow installed from inside a method keeps that
/// method's lexical `this` — the emitter must NOT rebind it.
#[test]
fn orchestrated_arrow_listener_keeps_lexical_this() {
    let lines = console_lines(
        "ext-asw4m3-arrow",
        r#"
        const { EventEmitter } = require('events');
        const e = new EventEmitter();
        const holder = {
            tag: 'H',
            install(target) {
                target.on('b', () => { console.log('arrow:' + this.tag); });
            }
        };
        holder.install(e);
        e.emit('b');
        "#,
    );
    assert_eq!(lines, vec!["arrow:H".to_string()]);
}

/// Both listener kinds on one emitter, dispatched in registration order:
/// the receiver binding and the lexical binding must not bleed into each
/// other across a mixed listener table.
#[test]
fn orchestrated_mixed_listeners_keep_their_own_this() {
    let lines = console_lines(
        "ext-asw4m3-mixed",
        r#"
        const { EventEmitter } = require('events');
        const e = new EventEmitter();
        e.on('tick', function () { console.log('fn:' + (this === e)); });
        const holder = {
            tag: 'H',
            install(target) {
                target.on('tick', () => { console.log('arrow:' + this.tag); });
            }
        };
        holder.install(e);
        console.log('emitted:' + e.emit('tick'));
        "#,
    );
    assert_eq!(
        lines,
        vec![
            "fn:true".to_string(),
            "arrow:H".to_string(),
            "emitted:true".to_string(),
        ]
    );
}
