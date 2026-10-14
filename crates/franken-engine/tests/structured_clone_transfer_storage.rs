//! Native parse/lower/execute checks for moved structuredClone transfer storage.
//! The companion reference runner executes these exact JS programs in Node;
//! only these native tests execute the modified Rust implementation.
#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

fn check(source: &str, expected: &[&str], memory_limit: Option<u64>) {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "clone-transfer-storage.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("storage fixture parses");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "clone-transfer-storage.js"),
        &LoweringContext::new("clone-transfer-storage", "transfer", "builtin-only"),
    )
    .expect("storage fixture lowers")
    .ir3;
    for v8_profile in [false, true] {
        for stress in [None, Some(7)] {
            let mut config = if v8_profile {
                InterpreterConfig::v8_defaults()
            } else {
                InterpreterConfig::quickjs_defaults()
            };
            config.instruction_budget = 10_000_000;
            if let Some(limit) = memory_limit {
                config.max_total_memory_bytes = limit;
            }
            config.granted_capabilities = [
                RuntimeCapability::VmDispatch,
                RuntimeCapability::HeapAllocate,
                RuntimeCapability::Builtin,
                RuntimeCapability::Console,
            ]
            .into_iter()
            .collect();
            let mut core = InterpreterCore::new(config, "clone-transfer-storage");
            core.set_gc_stress_interval(stress);
            let result = core.execute(&module);
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes(),
                "storage accounting (v8={v8_profile}, GC={stress:?})"
            );
            let output: Vec<String> = result
                .expect("storage fixture executes")
                .console_output
                .into_iter()
                .map(|entry| entry.message)
                .collect();
            assert_eq!(output, expected, "v8={v8_profile}, GC={stress:?}");
        }
    }
}

const BUFFER_ONLY: &str = r#"
const buffer = new ArrayBuffer(4194304);
const bytes = new Uint8Array(buffer);
bytes[0] = 17;
bytes[4194303] = 91;
const orphan = new ArrayBuffer(4);
const source = {
  buffer,
  again: buffer,
  get last() { bytes[1] = 23; return 7; }
};
source.self = source;
const clone = structuredClone(source, { transfer: [buffer, orphan] });
const result = new Uint8Array(clone.buffer);
console.log(buffer.byteLength, orphan.byteLength, bytes.length);
console.log(clone.self === clone, clone.again === clone.buffer, clone.last);
console.log(result.length, result[0], result[1], result[4194303]);
"#;

#[test]
fn buffer_only_transfer_fits_without_a_second_payload() {
    // The source is 4 MiB; the entire runtime receives 6 MiB. A second
    // source-sized destination or temporary copy cannot fit this test.
    check(
        BUFFER_ONLY,
        &["0 0 0", "true true 7", "4194304 17 23 91"],
        Some(6_291_456),
    );
}

const RESIZABLE_NO_VIEWS: &str = r#"
const buffer = new ArrayBuffer(8, { maxByteLength: 64 });
const clone = structuredClone({
  get first() { buffer.resize(24); new Uint8Array(buffer)[23] = 51; return buffer; },
  buffer,
  get last() { buffer.resize(40); new Uint8Array(buffer)[39] = 73; return 1; }
}, { transfer: [buffer] });
console.log(buffer.byteLength, clone.first === clone.buffer);
console.log(clone.buffer.byteLength, clone.buffer.maxByteLength, clone.buffer.resizable);
console.log(new Uint8Array(clone.buffer)[23], new Uint8Array(clone.buffer)[39]);
clone.buffer.resize(48);
console.log(clone.buffer.byteLength, new Uint8Array(clone.buffer)[47]);
"#;

#[test]
fn viewless_resizable_transfers_move_the_final_backing_store() {
    check(
        RESIZABLE_NO_VIEWS,
        &["0 true", "40 64 true", "51 73", "48 0"],
        None,
    );
}

const EMPTY_TRACKING: &str = r#"
const buffer = new ArrayBuffer(0, { maxByteLength: 32 });
const tracking = new Uint8Array(buffer);
const data = new DataView(buffer);
const clone = structuredClone({ tracking, data, buffer,
  get grow() { buffer.resize(12); new Uint8Array(buffer)[11] = 55; return 1; }
}, { transfer: [buffer] });
console.log(buffer.byteLength, tracking.length);
console.log(clone.tracking.buffer === clone.buffer, clone.data.buffer === clone.buffer);
console.log(clone.buffer.byteLength, clone.tracking.length, clone.data.byteLength, clone.tracking[11]);
clone.buffer.resize(20);
console.log(clone.tracking.length, clone.data.byteLength);
"#;

#[test]
fn zero_length_tracking_views_still_materialize_their_late_sized_shell() {
    check(
        EMPTY_TRACKING,
        &["0 0", "true true", "12 12 12 55", "20 20"],
        None,
    );
}

const MIXED_SHELLS: &str = r#"
const large = new ArrayBuffer(1048576);
new Uint8Array(large)[1048575] = 19;
const small = new ArrayBuffer(8, { maxByteLength: 32 });
const fixed = new Uint16Array(small, 2, 2);
const tracking = new Uint8Array(small, 2);
const data = new DataView(small, 1);
const plain = new ArrayBuffer(4);
new Uint8Array(plain).set([2, 4, 6, 8]);
const plainView = new Uint8Array(plain, 1, 2);
const clone = structuredClone({ large, small, fixed, tracking, data, plainView,
  get later() { small.resize(12); new Uint8Array(small)[11] = 67; return 1; }
}, { transfer: [large, small, plain] });
console.log(large.byteLength, small.byteLength, plain.byteLength, fixed.length, plainView.length);
console.log(clone.large.byteLength, new Uint8Array(clone.large)[1048575]);
console.log(clone.fixed.buffer === clone.small, clone.tracking.buffer === clone.small, clone.data.buffer === clone.small);
console.log(clone.fixed.length, clone.tracking.length, clone.data.byteLength, clone.tracking[9]);
console.log(clone.plainView.byteOffset, clone.plainView.length, Array.from(clone.plainView).join(','));
"#;

#[test]
fn a_transfer_batch_can_mix_empty_fixed_and_resizable_view_shells() {
    check(
        MIXED_SHELLS,
        &["0 0 0 0 0", "1048576 19", "true true true", "2 10 11 67", "1 2 4,6"],
        None,
    );
}

// Preserve the engine's pre-existing all-entry revalidation contract. It is
// stronger than HTML's sequential transfer phase; Node v22 also accepts this
// nested-detach case outright. The reference runner reports that discrepancy,
// rather than treating its output as a conformance pass.
const NESTED_REFUSAL: &str = r#"
const first = new ArrayBuffer(4);
const second = new ArrayBuffer(4);
new Uint8Array(first)[0] = 22;
new Uint8Array(second)[0] = 33;
let inner;
let outcome = 'success';
try {
  structuredClone({ first, second,
    get later() { inner = structuredClone(second, { transfer: [second] }); return 0; }
  }, { transfer: [first, second] });
} catch (error) {
  outcome = error.name + ':' + error.code;
}
console.log(outcome, first.byteLength, second.byteLength, inner.byteLength, new Uint8Array(inner)[0]);
"#;

#[test]
fn nested_detachment_preserves_the_existing_all_entry_prevalidation_contract() {
    check(NESTED_REFUSAL, &["DataCloneError:25 4 0 4 33"], None);
}

const THROWING_GETTER: &str = r#"
const first = new ArrayBuffer(4);
const second = new ArrayBuffer(4);
const sentinel = {};
let inner;
try {
  structuredClone({ first,
    get mutate() {
      inner = structuredClone(second, { transfer: [second] });
      new Uint8Array(first)[1] = 47;
      throw sentinel;
    }
  }, { transfer: [first] });
} catch (error) {
  console.log(error === sentinel, first.byteLength, new Uint8Array(first)[1]);
}
console.log(second.byteLength, inner.byteLength);
"#;

#[test]
fn throwing_getters_preserve_outer_sources_and_keep_nested_side_effects() {
    check(THROWING_GETTER, &["true 4 47", "0 4"], None);
}

const CHAIN: &str = r#"
let buffer = new ArrayBuffer(4096, { maxByteLength: 8192 });
new Uint8Array(buffer)[4095] = 71;
for (let i = 0; i < 32; i++) {
  const old = buffer;
  const view = new Uint8Array(old);
  const source = i % 2 === 0 ? { buffer: old } : { buffer: old, view };
  const clone = structuredClone(source, { transfer: [old] });
  if (old.byteLength !== 0 || view.length !== 0) throw new Error('source remained attached');
  if (clone.view && clone.view.buffer !== clone.buffer) throw new Error('lost buffer identity');
  buffer = clone.buffer;
}
console.log(buffer.byteLength, buffer.maxByteLength, new Uint8Array(buffer)[4095]);
buffer.resize(8192);
console.log(buffer.byteLength, new Uint8Array(buffer)[4095], new Uint8Array(buffer)[8191]);
"#;

#[test]
fn repeated_transfers_keep_ownership_and_view_invalidation_consistent() {
    check(CHAIN, &["4096 8192 71", "8192 71 0"], None);
}

const FIXED_BATCH_VIEWS: &str = r#"
const buffers = [];
const bytes = [];
const windows = [];
const unrelated = new ArrayBuffer(8);
const unrelatedView = new Uint8Array(unrelated);
unrelatedView[0] = 211;
for (let i = 0; i < 48; i++) {
  const buffer = new ArrayBuffer(16);
  const view = new Uint8Array(buffer, 1, 7);
  view[0] = i + 1;
  buffers.push(buffer);
  bytes.push(view);
  windows.push(new DataView(buffer, 2, 4));
}
const order = buffers.slice().reverse();
let late;
const input = {
  buffers,
  aliases: bytes,
  get final() {
    late = new Uint8Array(buffers[7], 3, 2);
    late[0] = 99;
    return 17;
  }
};
const clone = structuredClone(input, {transfer: order});
let checksum = 0;
let sharing = true;
let detachedViews = 0;
let dataErrors = 0;
for (let i = 0; i < buffers.length; i++) {
  checksum += clone.aliases[i][0];
  sharing = sharing && clone.aliases[i].buffer === clone.buffers[i];
  if (buffers[i].byteLength === 0 && bytes[i].length === 0 && bytes[i].byteOffset === 0) detachedViews++;
  try { windows[i].byteLength; } catch (e) { if (e instanceof TypeError) dataErrors++; }
}
console.log(checksum, sharing, detachedViews, dataErrors);
console.log(clone.final, late.length, new Uint8Array(clone.buffers[7])[3]);
console.log(unrelated.byteLength, unrelatedView.length, unrelatedView[0]);
"#;

#[test]
fn fixed_batch_discovers_every_alias_after_the_final_getter() {
    check(
        FIXED_BATCH_VIEWS,
        &["1176 true 48 48", "17 0 99", "8 8 211"],
        None,
    );
}

const MIXED_BATCH_FALLBACK: &str = r#"
const fixed = new ArrayBuffer(8);
const growing = new ArrayBuffer(4, {maxByteLength: 16});
const fixedView = new Uint8Array(fixed);
const tracking = new Uint8Array(growing);
fixedView[0] = 31;
tracking[0] = 47;
const clone = structuredClone({fixedView, tracking}, {transfer: [growing, fixed]});
console.log(fixed.byteLength, growing.byteLength, fixedView.length, tracking.length);
console.log(clone.fixedView[0], clone.tracking[0], clone.tracking.buffer.resizable);
clone.tracking.buffer.resize(8);
console.log(clone.tracking.length, clone.tracking[0], clone.tracking[7]);
"#;

#[test]
fn mixed_transfer_lists_keep_resizable_view_semantics() {
    check(
        MIXED_BATCH_FALLBACK,
        &["0 0 0 0", "31 47 true", "8 47 0"],
        None,
    );
}
