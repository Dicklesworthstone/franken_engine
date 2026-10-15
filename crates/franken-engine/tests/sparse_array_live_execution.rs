#![forbid(unsafe_code)]

//! Public source-to-runtime sparse Array regressions. Reference execution is
//! not Rust execution: run these tests on both native profiles with Cargo.

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore, InterpreterError};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::{Ir0Module, Ir3Module};
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

fn compile(source: &str) -> Ir3Module {
    let tree = CanonicalEs2020Parser.parse_with_options(
        ParserSource { label: "sparse-array.js".into(), text: source.into() },
        ParseGoal::Script,
        &ParserOptions::default(),
    ).expect("sparse Array source must parse");
    lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "sparse-array.js"),
        &LoweringContext::new("sparse-array-trace", "sparse-array-decision", "sparse-array-policy"),
    ).expect("sparse Array source must lower").ir3
}

fn interpreter(v8: bool, stress: Option<u64>) -> InterpreterCore {
    let mut config = if v8 { InterpreterConfig::v8_defaults() } else { InterpreterConfig::quickjs_defaults() };
    // Never increase either profile's budget to hide a linear hole scan.
    config.instruction_budget = config.instruction_budget.min(100_000);
    config.granted_capabilities = [
        RuntimeCapability::VmDispatch, RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin, RuntimeCapability::Console,
    ].into_iter().collect();
    let mut core = InterpreterCore::new(config, "sparse-array");
    core.set_gc_stress_interval(stress);
    core
}

fn assert_source(source: &str, expected: &str) {
    for length in [1_048_576_u64, u64::from(u32::MAX)] {
        let source = source.replace("__LENGTH__", &length.to_string());
        let module = compile(&source);
        for v8 in [false, true] {
            for stress in [None, Some(1), Some(7)] {
                let mut core = interpreter(v8, stress);
                let result = core.execute(&module).unwrap_or_else(|error| {
                    panic!("length={length}, v8={v8}, GC={stress:?}: {error:?}\n{source}")
                });
                assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes(),
                    "memory accounting: length={length}, v8={v8}, GC={stress:?}");
                let lines: Vec<_> = result.console_output.into_iter().map(|entry| entry.message).collect();
                assert_eq!(lines, [expected], "length={length}, v8={v8}, GC={stress:?}");
            }
        }
    }
}

macro_rules! source_case {
    ($name:ident, $source:expr, $expected:expr) => {
        #[test]
        fn $name() { assert_source($source, $expected); }
    };
}

source_case!(all_hole_skipping_reads_use_real_sparse_array_elements, r#"
const n = __LENGTH__;
const a = [];
a.length = n;
a[3] = 5;
a[n - 2] = 9;
const seen = [];
let receiverMatches = true;
a.forEach((value, index, receiver) => {
    seen.push(index + '=' + value);
    receiverMatches = receiverMatches && receiver === a;
});
const mapped = a.map(value => value * 2);
const filtered = a.filter(value => value > 5);
console.log([
    receiverMatches,
    seen.join(',') === '3=5,' + (n - 2) + '=9',
    mapped.length === n, !(0 in mapped), !(4 in mapped),
    mapped[3] === 10, mapped[n - 2] === 18,
    filtered.length === 1 && filtered[0] === 9,
    a.some(value => value === 9), a.every(value => value > 0),
    a.reduce((sum, value) => sum + value, 0) === 14,
    a.reduceRight((text, value) => text + value, '') === '95',
    a.indexOf(9) === n - 2, a.lastIndexOf(5) === 3,
    a.indexOf(undefined) === -1
].every(value => value));
"#, "true");

source_case!(empty_sparse_arrays_finish_without_invoking_callbacks, r#"
const a = [];
a.length = __LENGTH__;
let calls = 0;
const callback = () => { calls++; return true; };
const mapped = a.map(callback);
const filtered = a.filter(callback);
const some = a.some(callback);
const every = a.every(callback);
a.forEach(callback);
const initial = a.reduce(callback, 17);
const reverseInitial = a.reduceRight(callback, 18);
let errors = 0;
try { a.reduce(callback); } catch (error) { if (error instanceof TypeError) errors++; }
try { a.reduceRight(callback); } catch (error) { if (error instanceof TypeError) errors++; }
try { a.map(null); } catch (error) { if (error instanceof TypeError) errors++; }
console.log(calls === 0 && mapped.length === a.length && filtered.length === 0
    && !some && every && initial === 17 && reverseInitial === 18 && errors === 3
    && a.indexOf(1) === -1 && a.lastIndexOf(1) === -1);
"#, "true");

source_case!(callbacks_edit_future_indices_without_changing_captured_length, r#"
const n = __LENGTH__;
const a = [];
a.length = n;
a[1] = 1;
a[n - 2] = 9;
const seen = [];
a.forEach((value, index) => {
    seen.push(index + '=' + value);
    if (index === 1) {
        delete a[n - 2];
        a.length = 40001;
        a[40000] = 3;
        a[n] = 99;
        delete a[1];
        a[1] = 8;
    }
});
console.log(seen.join(',') === '1=1,40000=3');
"#, "true");

source_case!(reverse_reduction_observes_new_lower_indices, r#"
const n = __LENGTH__;
const a = [];
a.length = n;
a[2] = 2;
a[n - 2] = 9;
const seen = [];
const total = a.reduceRight((sum, value, index, receiver) => {
    if (receiver !== a) throw new Error('wrong receiver');
    seen.push(value);
    if (value === 9) { a[40000] = 7; delete a[2]; }
    return sum + value;
}, 0);
console.log(total === 16 && seen.join(',') === '9,7');
"#, "true");

source_case!(inherited_accessors_and_shadowing_survive_sparse_jumps, r#"
const a = [];
a.length = __LENGTH__;
a[3] = 2;
a[50000] = 6;
const prototype = [];
let calls = 0;
Object.defineProperty(prototype, '40000', {
    get() { calls++; a[60000] = 7; return this === a ? 5 : -1; }, configurable: true
});
Object.defineProperty(prototype, '50000', {
    get() { throw new Error('shadowed getter ran'); }, configurable: true
});
Object.setPrototypeOf(a, prototype);
const seen = [];
a.forEach((value, index) => seen.push(index + '=' + value));
console.log(calls === 1 && seen.join(',') === '3=2,40000=5,50000=6,60000=7');
"#, "true");

source_case!(a_callback_can_replace_the_prototype_before_the_next_gap, r#"
const n = __LENGTH__;
const a = [];
a.length = n;
a[3] = 1;
a[n - 2] = 9;
const nextPrototype = [];
nextPrototype[40000] = 4;
const seen = [];
a.forEach((value, index) => {
    seen.push(value);
    if (index === 3) Object.setPrototypeOf(a, nextPrototype);
});
console.log(seen.join(',') === '1,4,9');
"#, "true");

source_case!(species_and_result_definitions_cannot_stale_the_index_walk, r#"
const n = __LENGTH__;
const a = [];
a.length = n;
a[3] = 1;
a[n - 2] = 9;
let suppliedLength = 0;
const writes = [];
a.constructor = { [Symbol.species]: function(length) {
    suppliedLength = length;
    a[40000] = 4;
    return new Proxy({}, {
        defineProperty(target, key, descriptor) {
            writes.push(key);
            if (key === '3') { a[50000] = 5; delete a[n - 2]; }
            return Reflect.defineProperty(target, key, descriptor);
        }
    });
} };
const result = a.map(value => value * 2);
console.log(suppliedLength === n && writes.join(',') === '3,40000,50000'
    && result[3] === 2 && result[40000] === 8 && result[50000] === 10
    && !('length' in result));
"#, "true");

source_case!(proxy_prototype_has_and_get_traps_are_not_skipped, r#"
const a = [];
a.length = __LENGTH__;
const seen = [];
Object.setPrototypeOf(a, new Proxy([], {
    has(target, key) {
        seen.push('h' + key);
        if (key === '3') throw 'stop';
        return key === '1';
    },
    get(target, key, receiver) {
        seen.push('g' + key);
        return key === '1' ? 17 : Reflect.get(target, key, receiver);
    }
}));
try { Array.prototype.forEach.call(a, (value, index) => seen.push('c' + index + '=' + value)); }
catch (error) { seen.push(error); }
console.log(seen.join(',') === 'h0,h1,g1,c1=17,h2,h3,stop');
"#, "true");

source_case!(hole_visiting_methods_and_typed_array_branding_keep_their_contracts, r#"
const a = [];
a.length = __LENGTH__;
a[2] = 3;
const seen = [];
const found = a.find((value, index) => { seen.push(index); return index === 1; });
let called = false;
let branded = false;
try { Uint8Array.prototype.map.call(a, () => { called = true; }); }
catch (error) { branded = error instanceof TypeError; }
console.log(found === undefined && seen.join(',') === '0,1'
    && a.includes(undefined) && branded && !called);
"#, "true");

source_case!(search_offset_coercion_occurs_before_live_index_selection, r#"
const n = __LENGTH__;
const a = [];
a.length = n;
a[n - 2] = 9;
let conversions = 0;
const index = a.indexOf(9, { valueOf() { conversions++; a[40000] = 9; return 4; } });
const reverse = a.lastIndexOf(9, { valueOf() { conversions++; delete a[n - 2]; return n; } });
console.log(index === 40000 && reverse === 40000 && conversions === 2);
"#, "true");

#[test]
fn proxy_fallback_resource_refusal_is_not_a_guest_exception() {
    let module = compile(r#"
const a = [];
a.length = 4294967295;
const receiver = new Proxy(a, { has() { return false; } });
try { Array.prototype.forEach.call(receiver, () => {}); }
catch (error) { console.log('caught host refusal'); }
console.log('continued after refusal');
"#);
    for v8 in [false, true] {
        let mut core = interpreter(v8, None);
        assert!(matches!(core.execute(&module), Err(InterpreterError::BudgetExhausted { .. })));
        assert!(core.console_output().is_empty());
        assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
    }
}

source_case!(slice_preserves_holes_and_rebases_only_present_indices, r#"
const n = __LENGTH__;
const a = [];
a.length = n;
a[7] = 3;
a[n - 2] = 9;
const result = a.slice(2, n - 1);
const empty = a.slice(8, n - 2);
console.log(result.length === n - 3 && !(0 in result) && !(6 in result)
    && result[5] === 3 && result[n - 4] === 9
    && empty.length === n - 10 && empty.indexOf(3) === -1 && empty.indexOf(9) === -1
    && a.length === n && a[7] === 3 && a[n - 2] === 9);
"#, "true");

source_case!(slice_result_definitions_recheck_the_live_source_and_set_final_length, r#"
const n = __LENGTH__;
const a = [];
a.length = n;
a[3] = 3;
a[n - 2] = 9;
const seen = [];
a.constructor = { [Symbol.species]: function(length) {
    seen.push(length === n - 3 ? 'species' : 'bad-length');
    return new Proxy({}, { defineProperty(target, key, descriptor) {
        seen.push(key);
        if (key === '1') { a[50000] = 5; delete a[n - 2]; }
        return Reflect.defineProperty(target, key, descriptor);
    } });
} };
const start = { valueOf() { seen.push('start'); a[40000] = 4; return 2; } };
const end = { valueOf() { seen.push('end'); return n - 1; } };
const result = a.slice(start, end);
console.log(seen.join(',') === 'start,end,species,1,39998,49998,length'
    && result.length === n - 3 && result[1] === 3
    && result[39998] === 4 && result[49998] === 5 && !(n - 4 in result));
"#, "true");

source_case!(concat_detects_a_sparse_argument_to_a_dense_receiver, r#"
const n = __LENGTH__ - 2;
const a = [];
a.length = n;
a[3] = 3;
a[n - 2] = 9;
const result = [11].concat(a, 13);
console.log(result.length === n + 2 && result[0] === 11 && !(1 in result)
    && result[4] === 3 && result[n - 1] === 9 && result[n + 1] === 13
    && !(n in result) && a.length === n);
"#, "true");

source_case!(concat_spreadability_overrides_and_plain_array_likes_remain_live, r#"
const n = __LENGTH__;
const a = [];
a.length = n;
a[7] = 3;
a[Symbol.isConcatSpreadable] = false;
const unspread = [].concat(a);
const ordinary = { length: n - 1, 3: 7, [Symbol.isConcatSpreadable]: true };
const spread = [11].concat(ordinary);
console.log(unspread.length === 1 && unspread[0] === a
    && spread.length === n && spread[0] === 11 && spread[4] === 7
    && !(1 in spread) && !(n - 1 in spread));
"#, "true");

source_case!(concat_source_getters_and_result_traps_insert_future_elements, r#"
const n = __LENGTH__;
const a = [];
a.length = n;
a[3] = 'a';
Object.defineProperty(a, '40000', { get() { a[60000] = 'c'; return 'b'; }, configurable: true });
const outer = [];
const writes = [];
outer.constructor = { [Symbol.species]: function(length) {
    if (length !== 0) throw new Error('concat species length');
    return new Proxy({}, { defineProperty(target, key, descriptor) {
        writes.push(key);
        if (key === '3') a[50000] = 'z';
        return Reflect.defineProperty(target, key, descriptor);
    } });
} };
const result = outer.concat(a);
console.log(writes.join(',') === '3,40000,50000,60000,length'
    && result.length === n && result[3] === 'a' && result[40000] === 'b'
    && result[50000] === 'z' && result[60000] === 'c');
"#, "true");

source_case!(slice_final_length_refusal_preserves_prior_result_writes, r#"
const n = __LENGTH__;
const a = [];
a.length = n;
a[7] = 3;
a[n - 2] = 9;
let result;
a.constructor = { [Symbol.species]: function() {
    result = {};
    Object.defineProperty(result, 'length', { value: 0, writable: false });
    return result;
} };
let failed = false;
try { a.slice(); } catch (error) { failed = error instanceof TypeError; }
console.log(failed && result[7] === 3 && result[n - 2] === 9 && result.length === 0);
"#, "true");

source_case!(sparse_concat_does_not_relax_the_array_length_limit, r#"
const n = __LENGTH__;
const a = [];
a.length = n;
a[n - 1] = 9;
let correct = false;
try {
    const result = [1].concat(a);
    correct = n < 4294967295 && result.length === n + 1 && result[n] === 9;
} catch (error) {
    correct = n === 4294967295 && error instanceof RangeError;
}
console.log(correct);
"#, "true");
