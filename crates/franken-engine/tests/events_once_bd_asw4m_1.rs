//! bd-asw4m.1: Promise-backed static `events.once` through the shared
//! EventEmitter and Promise/event-loop machinery.
//!
//! The supported export is lowering-only pure compute: confirmed CommonJS
//! destructures/module aliases and the `node:events` ESM named import become a
//! `builtin:EventsOnce` hostcall. No general-purpose module object or
//! `ModuleLoad` authority is materialized.

use std::collections::BTreeSet;

use frankenengine_engine::HybridRouter;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::{EffectBoundary, Ir0Module, Ir1Op, Ir3Instruction};
use frankenengine_engine::lowering_pipeline::{
    LoweringContext, lower_ir0_to_ir1, lower_ir0_to_ir3, lower_ir1_to_ir2,
};

fn eval_console(source: &str) -> String {
    let mut engine = HybridRouter::default();
    let outcome = engine
        .eval(source)
        .unwrap_or_else(|error| panic!("events.once eval failed for {source:?}: {error}"));
    outcome
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect::<Vec<_>>()
        .join("\n")
}

fn eval_error(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => {
            panic!("expected events.once source to be refused: {source:?}; got {outcome:?}")
        }
        Err(error) => error.to_string(),
    }
}

fn execute_core(source: &str) -> InterpreterCore {
    let tree = frankenengine_engine::parser_api_stability::parse_script(source)
        .expect("parse events.once memory-accounting source");
    let ir0 = Ir0Module::from_syntax_tree(tree, "events_once_memory_accounting.js");
    let output = lower_ir0_to_ir3(
        &ir0,
        &LoweringContext::new("events-once-memory", "bd-asw4m.1", "pure-builtin"),
    )
    .expect("lower events.once memory-accounting source");
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
    ]);
    let mut core = InterpreterCore::new(config, "events-once-memory");
    core.execute(&output.ir3)
        .expect("execute events.once memory-accounting source");
    core
}

#[test]
fn commonjs_once_resolves_with_every_emitted_argument() {
    // franken_node compatibility-corpus events fixture 0019.
    let source = r#"
        const { once, EventEmitter } = require('events');
        const emitter = new EventEmitter();
        setImmediate(() => emitter.emit('ready', 'val', 42));
        (async () => {
          const values = await once(emitter, 'ready');
          console.log(values.length + ':' + values[0] + ':' + values[1]);
        })();
    "#;
    assert_eq!(eval_console(source), "2:val:42");
}

#[test]
fn commonjs_once_rejects_with_the_original_error_object() {
    // franken_node compatibility-corpus events fixture 0030.
    let source = r#"
        const { once, EventEmitter } = require('events');
        const emitter = new EventEmitter();
        const original = new Error('bad');
        setImmediate(() => emitter.emit('error', original));
        (async () => {
          try {
            await once(emitter, 'ready');
            console.log('wrong');
          } catch (error) {
            console.log((error === original) + ':' + error.message);
          }
        })();
    "#;
    assert_eq!(eval_console(source), "true:bad");
}

#[test]
fn requested_event_and_error_links_are_removed_together() {
    let source = r#"
        const { once, EventEmitter } = require('events');
        const resolved = new EventEmitter();
        const rejected = new EventEmitter();
        (async () => {
          const ready = once(resolved, 'ready');
          resolved.emit('ready', 'ok');
          console.log((await ready)[0]);

          const later = new Error('later');
          try {
            resolved.emit('error', later);
          } catch (error) {
            console.log('unlinked-error:' + (error === later));
          }
          console.log('resolved-link:' + resolved.emit('ready', 'stale'));

          const never = once(rejected, 'never');
          const original = new Error('reject');
          console.log('handled-error:' + rejected.emit('error', original));
          try {
            await never;
          } catch (error) {
            console.log('same-rejection:' + (error === original));
          }
          console.log('rejected-link:' + rejected.emit('never', 'stale'));
        })();
    "#;
    assert_eq!(
        eval_console(source),
        "ok\nunlinked-error:true\nresolved-link:false\nhandled-error:true\nsame-rejection:true\nrejected-link:false"
    );
}

#[test]
fn once_settlement_queues_promise_reactions_as_microtasks() {
    let source = r#"
        const { once, EventEmitter } = require('events');
        const emitter = new EventEmitter();
        const order = [];
        once(emitter, 'ready').then(() => order.push('once'));
        emitter.emit('ready');
        order.push('sync');
        queueMicrotask(() => order.push('queued'));
        setImmediate(() => console.log(order.join(',')));
    "#;
    assert_eq!(eval_console(source), "sync,once,queued");
}

#[test]
fn commonjs_module_alias_routes_to_the_same_builtin() {
    let source = r#"
        const events = require('node:events');
        const { EventEmitter } = require('events');
        const emitter = new EventEmitter();
        events.once(emitter, 'done').then((args) => console.log(args.join(':')));
        emitter.emit('done', 'alias', 7);
    "#;
    assert_eq!(eval_console(source), "alias:7");
}

#[test]
fn awaiting_error_itself_resolves_instead_of_rejecting() {
    let source = r#"
        const { once, EventEmitter } = require('events');
        const emitter = new EventEmitter();
        const original = new Error('observed');
        once(emitter, 'error').then((args) => {
          console.log((args[0] === original) + ':' + args[0].message);
        });
        emitter.emit('error', original);
    "#;
    assert_eq!(eval_console(source), "true:observed");
}

#[test]
fn waiter_memory_accounting_matches_eager_reference_before_and_after_cleanup() {
    let pending = execute_core(
        "const { once, EventEmitter } = require('events'); const emitter = new EventEmitter(); once(emitter, 'pending');",
    );
    assert_eq!(
        pending.estimated_memory_bytes(),
        pending.recompute_estimated_memory_bytes()
    );

    let settled = execute_core(
        "const { once, EventEmitter } = require('events'); const emitter = new EventEmitter(); once(emitter, 'ready'); emitter.emit('ready', 'ok');",
    );
    assert_eq!(
        settled.estimated_memory_bytes(),
        settled.recompute_estimated_memory_bytes()
    );
}

#[test]
fn node_events_named_import_is_elided_to_a_builtin_capability() {
    let tree = frankenengine_engine::parser_api_stability::parse_module(
        "import { once as wait } from 'node:events';\nconst emitter = {};\nwait(emitter, 'ready');\n",
    )
    .expect("parse ESM events.once module");
    let ir0 = Ir0Module::from_syntax_tree(tree, "events_once_named_import.mjs");
    let ir1 = lower_ir0_to_ir1(&ir0).expect("lower supported events.once ESM import");

    assert!(ir1.module.ops.iter().any(|op| matches!(op,
        Ir1Op::HostCall { capability, arg_count: 2 }
            if capability == "builtin:EventsOnce"
    )));
    assert!(!ir1.module.ops.iter().any(|op| matches!(op,
        Ir1Op::ImportModule { specifier } if specifier == "node:events"
    )));

    let ir2 = lower_ir1_to_ir2(&ir1.module).expect("annotate events.once capability");
    let once_op = ir2
        .module
        .ops
        .iter()
        .find(|op| {
            matches!(&op.inner,
                Ir1Op::HostCall { capability, .. } if capability == "builtin:EventsOnce"
            )
        })
        .expect("events.once IR2 hostcall");
    assert_eq!(once_op.effect, EffectBoundary::HostcallEffect);
    assert_eq!(
        once_op
            .required_capability
            .as_ref()
            .map(|capability| capability.0.as_str()),
        Some("builtin:EventsOnce")
    );
}

#[test]
fn async_function_lowering_emits_a_real_await_instruction() {
    let tree = frankenengine_engine::parser_api_stability::parse_module(
        "import { once as wait } from 'node:events';\nasync function waitFor(emitter) { return await wait(emitter, 'ready'); }\n",
    )
    .expect("parse async ESM events.once source");
    let ir0 = Ir0Module::from_syntax_tree(tree, "events_once_async_lowering.mjs");
    let output = lower_ir0_to_ir3(
        &ir0,
        &LoweringContext::new("events-once", "bd-asw4m.1", "pure-builtin"),
    )
    .expect("lower async ESM events.once source");

    assert!(!output.ir1.ops.iter().any(|op| matches!(op,
        Ir1Op::ImportModule { specifier } if specifier == "node:events"
    )));
    assert!(
        output
            .ir3
            .instructions
            .iter()
            .any(|instruction| matches!(instruction, Ir3Instruction::AwaitValue { .. }))
    );
}

#[test]
fn unsupported_or_first_class_events_once_shapes_stay_fail_closed() {
    for source in [
        "const { once } = require('events'); const saved = once; console.log(typeof saved);",
        "const events = require('events'); const saved = events.once; console.log(typeof saved);",
        "const events = require('events'); const e = {}; events['once'](e, 'x');",
        "const name = 'events'; const events = require(name); console.log(events);",
    ] {
        let error = eval_error(source);
        assert!(
            error.contains("ambient authority violation"),
            "unsupported events.once shape must remain ambient-refused, got: {error}"
        );
    }

    for source in [
        "import { once } from 'node:events';\nconsole.log(typeof once);\n",
        "import events from 'node:events';\nconst emitter = {};\nevents.once(emitter, 'x');\n",
    ] {
        let tree = frankenengine_engine::parser_api_stability::parse_module(source)
            .expect("parse unsupported ESM events shape");
        let ir0 = Ir0Module::from_syntax_tree(tree, "unsupported_events_once.mjs");
        let ir1 = lower_ir0_to_ir1(&ir0).expect("unsupported ESM shape stays an explicit import");
        assert!(ir1.module.ops.iter().any(|op| matches!(op,
            Ir1Op::ImportModule { specifier } if specifier == "node:events"
        )));
        assert!(!ir1.module.ops.iter().any(|op| matches!(op,
            Ir1Op::HostCall { capability, .. } if capability == "builtin:EventsOnce"
        )));
    }
}
