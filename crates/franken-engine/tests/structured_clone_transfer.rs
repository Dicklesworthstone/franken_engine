//! Public native parse/lower/execute regressions for structuredClone transfers.
//! scripts/test_structured_clone_transfer_reference.cjs runs these exact programs
//! under Node only to verify their expected observations, not native execution.
#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

fn check(source: &str, expected: &[&str]) {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "clone-transfer.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("transfer fixture parses");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "clone-transfer.js"),
        &LoweringContext::new("clone-transfer", "transfer", "builtin-only"),
    )
    .expect("transfer fixture lowers")
    .ir3;
    for v8_profile in [false, true] {
        for stress in [None, Some(7)] {
            let mut config = if v8_profile {
                InterpreterConfig::v8_defaults()
            } else {
                InterpreterConfig::quickjs_defaults()
            };
            config.instruction_budget = 10_000_000;
            config.granted_capabilities = [
                RuntimeCapability::VmDispatch,
                RuntimeCapability::HeapAllocate,
                RuntimeCapability::Builtin,
                RuntimeCapability::Console,
            ]
            .into_iter()
            .collect();
            let mut core = InterpreterCore::new(config, "clone-transfer");
            core.set_gc_stress_interval(stress);
            let result = core.execute(&module);
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes(),
                "transfer accounting (v8={v8_profile}, GC={stress:?})"
            );
            let output: Vec<String> = result
                .expect("transfer fixture executes")
                .console_output
                .into_iter()
                .map(|entry| entry.message)
                .collect();
            assert_eq!(output, expected, "v8={v8_profile}, GC={stress:?}");
        }
    }
}

const GRAPH: &str = r#"
const buffer = new ArrayBuffer(8);
new Uint8Array(buffer).set([1,2,3,4,5,6,7,8]);
const view = new Uint8Array(buffer, 2, 3);
const data = new DataView(buffer, 1, 4);
const orphan = new ArrayBuffer(2);
const source = { buffer, again: buffer, view, data };
source.self = source;
source.map = new Map([[buffer, view], [source, buffer]]);
const clone = structuredClone(source, { transfer: new Set([buffer, orphan]) });
console.log(buffer.byteLength, orphan.byteLength, view.length, view.byteLength);
console.log(clone.self === clone, clone.again === clone.buffer, clone.view.buffer === clone.buffer);
console.log(clone.map.get(clone.buffer) === clone.view, clone.map.get(clone) === clone.buffer);
console.log(clone.view.byteOffset, clone.view.length, Array.from(clone.view).join(','));
console.log(clone.data.buffer === clone.buffer, clone.data.byteOffset, clone.data.getUint8(0));
try { data.getUint8(0); } catch (e) { console.log(e.name); }
"#;

#[test]
fn transfers_keep_graph_aliases_and_detach_all_original_views() {
    check(GRAPH, &["0 0 0 0", "true true true", "true true", "2 3 3,4,5", "true 1 2", "TypeError"]);
}

const LATE_BYTES: &str = r#"
const buffer = new ArrayBuffer(4);
const bytes = new Uint8Array(buffer);
const log = [];
const clone = structuredClone({
  buffer,
  get first() { log.push('first'); bytes[0] = 17; return { get nested() { log.push('nested'); bytes[1] = 23; return 1; } }; },
  get last() { log.push('last'); bytes[3] = 42; return 2; }
}, { transfer: [buffer] });
console.log(log.join(','), buffer.byteLength, Array.from(new Uint8Array(clone.buffer)).join(','));
const empty = new ArrayBuffer(0);
const emptyClone = structuredClone(empty, { transfer: [empty] });
console.log(emptyClone.byteLength, emptyClone !== empty);
try { structuredClone(empty, { transfer: [empty] }); } catch (e) { console.log(e.name, e.code); }
"#;

#[test]
fn transferred_bytes_are_read_after_all_graph_getters() {
    check(LATE_BYTES, &["first,nested,last 0 17,23,0,42", "0 true", "DataCloneError 25"]);
}

const RESIZABLE: &str = r#"
const buffer = new ArrayBuffer(8, { maxByteLength: 24 });
const fixed = new Uint16Array(buffer, 2, 2);
const tracking = new Uint8Array(buffer, 2);
const data = new DataView(buffer, 1);
const clone = structuredClone({ fixed, tracking, data, buffer,
  get later() { buffer.resize(12); new Uint8Array(buffer)[11] = 91; return 1; }
}, { transfer: [buffer] });
console.log(buffer.byteLength, fixed.length, tracking.length);
console.log(clone.buffer.resizable, clone.buffer.maxByteLength, clone.buffer.byteLength);
console.log(clone.fixed.length, clone.tracking.length, clone.data.byteLength, clone.tracking[9]);
clone.buffer.resize(16);
console.log(clone.fixed.length, clone.tracking.length, clone.data.byteLength);
const copied = structuredClone(clone);
copied.buffer.resize(20);
console.log(copied.fixed.length, copied.tracking.length, copied.data.byteLength, clone.buffer.byteLength);
const early = new ArrayBuffer(4, { maxByteLength: 16 });
const earlyView = new Uint16Array(early);
const earlyClone = structuredClone({ get view() { early.resize(12); return earlyView; } }, { transfer: [early] });
console.log(earlyClone.view.buffer.resizable, earlyClone.view.length, earlyClone.view.buffer.byteLength, earlyView.length);
"#;

#[test]
fn resizable_buffers_keep_maximum_and_tracking_view_bounds() {
    check(RESIZABLE, &["0 0 0", "true 24 12", "2 10 11 91", "2 14 15", "2 18 19 16", "true 6 12 0"]);
}

const FAILURES: &str = r#"
const buffer = new ArrayBuffer(4);
const sentinel = {};
let reads = 0;
const source = { get value() { reads++; return 1; } };
for (const transfer of [[buffer, buffer], [new Uint8Array(1)], [new SharedArrayBuffer(1)], [{}], [function () {}]]) {
  try { structuredClone(source, { transfer }); }
  catch (e) { console.log(e.name, e.code, reads, buffer.byteLength); }
}
try { structuredClone({ get value() { throw sentinel; } }, { transfer: [buffer] }); }
catch (e) { console.log(e === sentinel, buffer.byteLength); }
try { structuredClone({ value: Symbol('bad') }, { transfer: [buffer] }); }
catch (e) { console.log(e.name, e.code, buffer.byteLength); }
const detached = new ArrayBuffer(1);
structuredClone(detached, { transfer: [detached] });
try { structuredClone(source, { transfer: [buffer, detached] }); }
catch (e) { console.log(e.name, e.code, reads, buffer.byteLength); }
"#;

#[test]
fn invalid_lists_and_serialization_errors_do_not_detach_valid_sources() {
    check(FAILURES, &["DataCloneError 25 0 4", "DataCloneError 25 0 4", "DataCloneError 25 0 4", "DataCloneError 25 0 4", "DataCloneError 25 0 4", "true 4", "DataCloneError 25 4", "DataCloneError 25 0 4"]);
}

const ITERATOR: &str = r#"
const log = [];
let gets = 0;
let nextGets = 0;
const buffer = new ArrayBuffer(2);
const orphan = new ArrayBuffer(1);
const list = {
  get [Symbol.iterator]() {
    gets++;
    return function () {
      log.push(this === list ? 'receiver' : 'wrong');
      let index = 0;
      return {
        get next() { nextGets++; return function () {
          log.push('next' + index);
          if (index === 0) { index++; return { value: buffer, done: false }; }
          if (index === 1) { index++; return { value: orphan, done: false }; }
          return { done: true };
        }; }
      };
    };
  }
};
const options = { get transfer() { log.push('transfer'); return list; } };
const clone = structuredClone({ get buffer() { log.push('graph'); return buffer; } }, options);
console.log(log.join(','), gets, nextGets, buffer.byteLength, orphan.byteLength, clone.buffer.byteLength);
const boom = {};
let graphReads = 0;
try { structuredClone({ get x() { graphReads++; } }, { get transfer() { throw boom; } }); }
catch (e) { console.log(e === boom, graphReads); }
"#;

#[test]
fn options_and_iterator_protocol_are_observable_once_before_serialization() {
    check(ITERATOR, &["transfer,receiver,next0,next1,next2,graph 1 1 0 0 2", "true 0"]);
}

const OPTIONS: &str = r#"
console.log(structuredClone(7), structuredClone(8, null), structuredClone(9, {}));
for (const options of [1, 'bad', true, { transfer: null }, { transfer: 1 }, { transfer: 'bad' }, { transfer: { length: 0 } }, { transfer: [1] }]) {
  try { structuredClone(1, options); }
  catch (e) { console.log(e.name, e.code); }
}
const list = [];
list[Symbol.iterator] = null;
try { structuredClone(1, { transfer: list }); }
catch (e) { console.log(e.name, e.code); }
"#;

#[test]
fn dictionary_and_sequence_validation_do_not_accept_array_like_fallbacks() {
    check(OPTIONS, &["7 8 9", "TypeError ERR_INVALID_ARG_TYPE", "TypeError ERR_INVALID_ARG_TYPE", "TypeError ERR_INVALID_ARG_TYPE", "TypeError ERR_INVALID_ARG_TYPE", "TypeError ERR_INVALID_ARG_TYPE", "TypeError ERR_INVALID_ARG_TYPE", "TypeError ERR_INVALID_ARG_TYPE", "TypeError ERR_INVALID_ARG_TYPE", "TypeError ERR_INVALID_ARG_TYPE"]);
}

const DIRECT_TRANSFER: &str = r#"
for (const method of ['transfer', 'transferToFixedLength']) {
  for (const length of [0, 2, 4, 8]) {
    const buffer = new ArrayBuffer(4, { maxByteLength: 8 });
    const view = new Uint8Array(buffer);
    view.set([1, 2, 3, 4]);
    const result = buffer[method](length);
    console.log(method, length, buffer.byteLength, view.length, result.resizable,
      result.maxByteLength, Array.from(new Uint8Array(result)).join(','));
  }
}
const buffer = new ArrayBuffer(4, { maxByteLength: 8 });
const result = buffer.transfer({ valueOf() {
  buffer.resize(6); new Uint8Array(buffer)[5] = 9; return 8;
} });
console.log(Array.from(new Uint8Array(result)).join(','), buffer.byteLength);
let held = new ArrayBuffer(1024);
new Uint8Array(held)[1023] = 71;
for (let i = 0; i < 32; i++) {
  const previous = held;
  held = previous.transfer();
  if (previous.byteLength !== 0) throw new Error('transfer did not detach');
}
const clone = structuredClone({ held }, { transfer: [held] });
console.log(held.byteLength, clone.held.byteLength, new Uint8Array(clone.held)[1023]);
"#;

#[test]
fn direct_transfers_and_structured_transfers_share_buffer_semantics() {
    check(DIRECT_TRANSFER, &["transfer 0 0 0 true 8 ", "transfer 2 0 0 true 8 1,2", "transfer 4 0 0 true 8 1,2,3,4", "transfer 8 0 0 true 8 1,2,3,4,0,0,0,0", "transferToFixedLength 0 0 0 false 0 ", "transferToFixedLength 2 0 0 false 2 1,2", "transferToFixedLength 4 0 0 false 4 1,2,3,4", "transferToFixedLength 8 0 0 false 8 1,2,3,4,0,0,0,0", "0,0,0,0,0,9,0,0 0", "0 1024 71"]);
}
