//! Clone graph snapshots must survive getters mutating their source containers.
//! The Node runner checks reference observations only, not this native path.

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
                label: "structured-clone-graph.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("clone graph fixture parses");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "structured-clone-graph.js"),
        &LoweringContext::new("clone-graph", "snapshot", "builtin-only"),
    )
    .expect("clone graph fixture lowers")
    .ir3;
    for v8_profile in [false, true] {
        for stress in [None, Some(7)] {
            let mut config = if v8_profile {
                InterpreterConfig::v8_defaults()
            } else {
                InterpreterConfig::quickjs_defaults()
            };
            config.granted_capabilities = [
                RuntimeCapability::VmDispatch,
                RuntimeCapability::HeapAllocate,
                RuntimeCapability::Builtin,
                RuntimeCapability::Console,
            ]
            .into_iter()
            .collect();
            let mut core = InterpreterCore::new(config, "clone-graph");
            core.set_gc_stress_interval(stress);
            let result = core.execute(&module);
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes(),
                "clone scratch accounting (v8={v8_profile}, GC={stress:?})"
            );
            let actual: Vec<String> = result
                .expect("clone graph executes")
                .console_output
                .into_iter()
                .map(|entry| entry.message)
                .collect();
            assert_eq!(actual, expected, "v8={v8_profile}, GC={stress:?}");
        }
    }
}

const SHRINK: &str = r#"
const source = [0, 1, 2];
source.length = 5;
Object.defineProperty(source, '0', {
  enumerable: true,
  get() { source.length = 1; return source; }
});
const clone = structuredClone(source);
console.log(source.length, clone.length, clone[0] === clone);
console.log(1 in clone, 2 in clone, 4 in clone, Object.keys(clone).join(','));
"#;

#[test]
fn array_length_is_captured_before_a_getter_shrinks_the_source() {
    check(SHRINK, &["1 5 true", "false false false 0"]);
}

const GROW: &str = r#"
const source = [0, 1];
source.length = 4;
Object.defineProperty(source, '0', {
  enumerable: true,
  get() { source[7] = 'late'; source.extra = 'late'; return 42; }
});
const clone = structuredClone(source);
console.log(source.length, clone.length, clone[0], clone[1]);
console.log(2 in clone, 7 in clone, 'extra' in clone, Object.keys(clone).join(','));
"#;

#[test]
fn array_growth_during_get_does_not_add_keys_or_trailing_holes() {
    check(GROW, &["8 4 42 1", "false false false 0,1"]);
}

const ENUMERABILITY: &str = r#"
for (const mode of ['hide', 'show']) {
  let reads = 0;
  const source = {
    get first() {
      Object.defineProperty(source, 'later', { enumerable: mode === 'show' });
      return 1;
    }
  };
  Object.defineProperty(source, 'later', {
    configurable: true,
    enumerable: mode === 'hide',
    get() { reads++; return 2; }
  });
  const clone = structuredClone(source);
  console.log(mode, JSON.stringify(clone), reads);
}
"#;

#[test]
fn getters_cannot_change_the_captured_enumerable_key_set() {
    check(ENUMERABILITY, &["hide {\"first\":1,\"later\":2} 1", "show {\"first\":1} 0"]);
}

const DELETE: &str = r#"
let inheritedReads = 0;
const prototype = { get later() { inheritedReads++; return 'wrong'; } };
const source = Object.create(prototype);
Object.defineProperty(source, 'first', {
  enumerable: true,
  get() { delete source.later; return 1; }
});
Object.defineProperty(source, 'later', { value: 2, enumerable: true, configurable: true });
const clone = structuredClone(source);
console.log(JSON.stringify(clone), inheritedReads, Object.hasOwn(clone, 'later'));
console.log(Object.getPrototypeOf(clone) === Object.prototype);
"#;

#[test]
fn deletion_skips_the_key_without_reading_an_inherited_replacement() {
    check(DELETE, &["{\"first\":1} 0 false", "true"]);
}

const RECREATE: &str = r#"
const shared = { token: 7 };
const source = {
  get first() {
    delete source.later;
    Object.defineProperty(source, 'later', { value: shared, enumerable: false });
    return shared;
  },
  later: 'original'
};
const clone = structuredClone(source);
console.log(Object.keys(clone).join(','), clone.first === clone.later, clone.later !== shared);
const descriptor = Object.getOwnPropertyDescriptor(clone, 'later');
console.log(descriptor.enumerable, descriptor.writable, descriptor.configurable, clone.later.token);
"#;

#[test]
fn recreated_selected_property_uses_its_current_value_even_when_hidden() {
    check(RECREATE, &["first,later true true", "true true true 7"]);
}

const DEPTH_FIRST: &str = r#"
const log = [];
const nested = { value: 2 };
const source = {
  get first() {
    log.push('first');
    Object.defineProperty(source, 'last', { enumerable: false });
    Object.defineProperty(nested, 'late', { enumerable: true, value: 3 });
    return { get child() { log.push('child'); return nested; } };
  },
  get last() { log.push('last'); return nested; }
};
const clone = structuredClone(source);
console.log(log.join(','), Object.keys(clone).join(','));
console.log(Object.keys(clone.last).join(','), clone.first.child === clone.last);
"#;

#[test]
fn each_container_takes_its_snapshot_when_first_reached_in_depth_first_order() {
    check(DEPTH_FIRST, &["first,child,last first,last", "value,late true"]);
}

const MAP_SNAPSHOT: &str = r#"
const source = new Map();
const first = {
  get value() {
    source.clear();
    source.set('late', 'not in clone');
    return 1;
  }
};
const second = { value: 2 };
source.set(first, first);
source.set(second, source);
const clone = structuredClone(source);
const entries = [...clone];
console.log(clone.size, source.size, entries[0][0] === entries[0][1]);
console.log(entries[1][0].value, entries[1][1] === clone, clone.has('late'));
"#;

#[test]
fn map_snapshots_keep_deleted_entries_and_shared_cycles_during_key_getters() {
    check(MAP_SNAPSHOT, &["2 1 true", "2 true false"]);
}

const SET_SNAPSHOT: &str = r#"
const source = new Set();
const first = { get value() { source.clear(); source.add('late'); return 1; } };
source.add(first);
source.add(source);
source.add({ value: 2 });
const clone = structuredClone(source);
const values = [...clone];
console.log(clone.size, source.size, values[0].value, values[1] === clone);
console.log(values[2].value, clone.has('late'));
"#;

#[test]
fn set_snapshot_is_not_a_live_iterator_over_guest_mutations() {
    check(SET_SNAPSHOT, &["3 1 1 true", "2 false"]);
}

const FILTERED: &str = r#"
let ignoredReads = 0;
const source = { get first() { return 1; } };
Object.defineProperty(source, Symbol('secret'), { enumerable: true, get() { ignoredReads++; return 9; } });
Object.defineProperty(source, 'hidden', { enumerable: false, get() { ignoredReads++; return 9; } });
const clone = structuredClone(source);
console.log(JSON.stringify(clone), ignoredReads, Object.getOwnPropertySymbols(clone).length);
"#;

#[test]
fn ignored_properties_are_never_evaluated() {
    check(FILTERED, &["{\"first\":1} 0 0"]);
}

const ABRUPT: &str = r#"
const original = { reason: 9 };
let reads = 0;
const source = { get first() { throw original; }, get later() { reads++; return 2; } };
for (let i = 0; i < 8; i++) {
  try { structuredClone(source); }
  catch (error) { if (error !== original) throw new Error('lost error identity'); }
}
try { structuredClone({ get value() { throw undefined; } }); }
catch (error) { console.log(error === undefined); }
console.log(reads, JSON.stringify(structuredClone({ good: [1, 2] })));
"#;

#[test]
fn abrupt_getters_preserve_identity_stop_the_walk_and_allow_later_clones() {
    check(ABRUPT, &["true", "0 {\"good\":[1,2]}"]);
}

const REENTRANT_CLONE: &str = r#"
const inner = { value: [1, 2] };
const source = {
  get first() { return structuredClone(inner); },
  get second() { return JSON.parse('{"other":3}'); },
  third: inner
};
const clone = structuredClone(source);
console.log(JSON.stringify(clone));
console.log(clone.first !== clone.third, clone.third !== inner);
"#;

#[test]
fn nested_clone_and_json_calls_preserve_outer_snapshot_ownership() {
    check(REENTRANT_CLONE, &["{\"first\":{\"value\":[1,2]},\"second\":{\"other\":3},\"third\":{\"value\":[1,2]}}", "true true"]);
}

const BINARY_GRAPH: &str = r#"
const buffer = new ArrayBuffer(8);
const bytes = new Uint8Array(buffer);
bytes[2] = 42;
const source = { buffer, first: new Uint8Array(buffer, 2, 3), second: new DataView(buffer, 1, 4) };
const clone = structuredClone(source);
console.log(clone.buffer !== buffer, clone.first.buffer === clone.buffer, clone.second.buffer === clone.buffer);
console.log(clone.first.byteOffset, clone.first.length, clone.first[0], clone.second.byteOffset, clone.second.byteLength);
clone.first[0] = 99;
console.log(bytes[2], new Uint8Array(clone.buffer)[2]);
"#;

#[test]
fn binary_scratch_does_not_break_shared_backing_buffer_identity() {
    check(BINARY_GRAPH, &["true true true", "2 3 42 1 4", "42 99"]);
}
