//! Native execution regressions for typed-array temporary memory and sorting.
#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{
    InterpreterConfig, InterpreterCore, InterpreterError, Value,
};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

fn check(source: &str, expected: &[&str], memory_limit: u64, memory_error: bool) {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "typed-array-memory.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("typed-array fixture parses");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "typed-array-memory.js"),
        &LoweringContext::new("typed-array-memory", "native", "builtin-only"),
    )
    .expect("typed-array fixture lowers")
    .ir3;
    for v8_profile in [false, true] {
        let mut config = if v8_profile {
            InterpreterConfig::v8_defaults()
        } else {
            InterpreterConfig::quickjs_defaults()
        };
        config.instruction_budget = 10_000_000;
        // Keep the fixed register carrier smaller than the tested payloads.
        config.max_registers = 256;
        config.max_total_memory_bytes = memory_limit;
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
            RuntimeCapability::Console,
        ]
        .into_iter()
        .collect();
        let mut core = InterpreterCore::new(config, "typed-array-memory");
        let result = core.execute(&module);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes(),
            "accounting drift (v8={v8_profile})"
        );
        if memory_error {
            assert!(
                matches!(result, Err(InterpreterError::MemoryBudgetExceeded { .. })),
                "expected typed memory refusal (v8={v8_profile}), got {result:?}"
            );
            let output: Vec<&str> = core
                .console_output()
                .iter()
                .map(|entry| entry.message.as_str())
                .collect();
            assert_eq!(output, expected, "refusal stage (v8={v8_profile})");
        } else {
            let output: Vec<String> = result
                .unwrap_or_else(|error| panic!("fixture executes (v8={v8_profile}): {error}"))
                .console_output
                .into_iter()
                .map(|entry| entry.message)
                .collect();
            assert_eq!(output, expected, "v8={v8_profile}");
        }
    }
}

#[test]
fn typed_array_sort_admits_expanded_values_before_allocating() {
    // The backing store fits easily. Its native Value carrier exceeds the
    // complete budget even before stable-sort scratch is considered.
    check("new Uint8Array(32768).sort();", &[], 524_288, true);
    check(
        "new Uint8Array(32768).toSorted(function() { throw Error('must not run'); });",
        &[],
        524_288,
        true,
    );
}

#[test]
fn comparator_allocations_include_both_retained_sort_carriers() {
    let slots = 8192 * std::mem::size_of::<Value>() as u64;
    let allocation = 262_144 + slots;
    let source = format!(
        "let retained; new Uint8Array(8192).sort(function(a, b) {{ if (retained === undefined) retained = new Uint8Array({allocation}); return a-b; }});"
    );
    // Each carrier and the callback's allocation fit on their own. Their
    // simultaneous footprint must be refused inside the first comparison.
    check(&source, &[], 262_144 + 2 * slots, true);
}

#[test]
fn default_sort_admits_its_scratch_in_addition_to_the_source() {
    let slots = 32768 * std::mem::size_of::<Value>() as u64;
    // Source materialization fits, but a second full carrier does not.
    check(
        "const source = new Uint8Array(32768); for (let i = 0; i < source.length; i++) source[i] = (i * 17) % 251; source.sort();",
        &[],
        slots + 262_144,
        true,
    );
}

#[test]
fn filter_kept_values_are_admitted_as_they_grow() {
    check(
        "new Uint8Array(32768).filter(function() { return true; });",
        &[],
        524_288,
        true,
    );
}

#[test]
fn iterable_constructor_cannot_accumulate_an_unbounded_native_list() {
    // Reuse the same iterator result so retained guest objects cannot be
    // the reason for refusal. Only the native numeric list keeps growing.
    check(
        r#"
        let index = 0;
        const result = { value: 7, done: false };
        const source = {
          [Symbol.iterator]() { return this; },
          next() { result.done = index++ >= 131072; return result; }
        };
        new Uint8Array(source);
        "#,
        &[],
        2_097_152,
        true,
    );
}

#[test]
fn invalid_comparator_is_checked_before_source_admission() {
    check(
        r#"
        const source = new Uint8Array(32768);
        try { source.sort(null); } catch (error) { console.log(error.name); }
        try { source.toSorted(7); } catch (error) { console.log(error.name); }
        "#,
        &["TypeError", "TypeError"],
        524_288,
        false,
    );
}

#[test]
fn byte_reordering_and_single_replacement_do_not_expand_the_source() {
    for (operation, expected) in [
        (
            "source.reverse(); console.log(source[0], source[131071]);",
            "91 17",
        ),
        (
            "source.copyWithin(1, 0, 131071); console.log(source[0], source[1], source[131071]);",
            "17 17 0",
        ),
        (
            "const copy = source.with(1, 23); console.log(copy[0], copy[1], copy[131071], source[1]);",
            "17 23 91 0",
        ),
        (
            "const copy = source.toReversed(); console.log(copy[0], copy[131071], source[0]);",
            "91 17 17",
        ),
    ] {
        let source = format!(
            "const source = new Uint8Array(131072); source[0] = 17; source[131071] = 91; {operation}"
        );
        check(&source, &[expected], 524_288, false);
    }
}

#[test]
fn reverse_and_overlapping_copy_preserve_nan_payload_bits() {
    check(
        r#"
        const bits = new Uint32Array([1, 2146959360, 2, 2146959360]);
        const values = new Float64Array(bits.buffer);
        values.reverse();
        console.log(bits[0], bits[1], bits[2], bits[3]);
        values.copyWithin(1, 0, 1);
        console.log(bits[0], bits[1], bits[2], bits[3]);
        "#,
        &["2 2146959360 1 2146959360", "2 2146959360 2 2146959360"],
        524_288,
        false,
    );
}

#[test]
fn byte_operations_keep_offsets_and_recheck_resized_view_bounds() {
    check(
        r#"
        const buffer = new ArrayBuffer(16, { maxByteLength: 32 });
        const all = new Uint16Array(buffer);
        all[0] = 111;
        all[1] = 222;
        const view = new Uint16Array(buffer, 4);
        view.set([10, 20, 30, 40, 50, 60]);
        view.copyWithin({ valueOf() { buffer.resize(12); return 1; } }, 0, 6);
        console.log(view.length, view.join(','), all[0], all[1]);
        view.reverse();
        console.log(view.join(','), all[0], all[1]);
        const fixed = new Uint16Array(buffer, 4, 4);
        try {
          fixed.copyWithin({ valueOf() { buffer.resize(10); return 0; } }, 1);
        } catch (error) { console.log(error.name, fixed.length, all[0], all[1]); }
        "#,
        &[
            "4 10,10,20,30 111 222",
            "30,20,10,10 111 222",
            "TypeError 0 111 222",
        ],
        1_048_576,
        false,
    );
}

#[test]
fn sort_comparator_result_runs_observable_number_conversion() {
    check(
        r#"
        let conversions = 0;
        const source = new Int16Array([4, 1, 3, 2]);
        const copy = source.toSorted(function(a, b) {
          return { [Symbol.toPrimitive](hint) {
            if (hint !== 'number') throw Error('wrong hint');
            conversions++;
            return a-b;
          }};
        });
        console.log(copy.join(','), source.join(','), conversions > 0);
        source.sort(function(a, b) { return { valueOf() { return String(a-b); } }; });
        console.log(source.join(','));
        const stable = new Int8Array([3, 1, 2]);
        stable.sort(function() { return { valueOf() { return NaN; } }; });
        console.log(stable.join(','));
        "#,
        &["1,2,3,4 4,1,3,2 true", "1,2,3,4", "3,1,2"],
        1_048_576,
        false,
    );
}

#[test]
fn bigint_and_symbol_comparator_results_throw_before_writeback() {
    check(
        r#"
        for (const result of [1n, Symbol('order')]) {
          const source = new Int8Array([2, 1]);
          try { source.sort(function() { return result; }); }
          catch (error) { console.log(error.name, source.join(',')); }
          try { source.toSorted(function() { return { valueOf() { return result; } }; }); }
          catch (error) { console.log(error.name, source.join(',')); }
        }
        "#,
        &[
            "TypeError 2,1",
            "TypeError 2,1",
            "TypeError 2,1",
            "TypeError 2,1",
        ],
        1_048_576,
        false,
    );
}

#[test]
fn abrupt_comparator_conversion_releases_all_temporary_reservations() {
    check(
        r#"
        let caught = 0;
        for (let index = 0; index < 16; index++) {
          const source = new Uint8Array(2048);
          try {
            source.sort(function() {
              return { valueOf() { throw Error('conversion failed'); } };
            });
          } catch (error) {
            if (error.message === 'conversion failed') caught++;
          }
        }
        console.log(caught, new Uint8Array(262144).length);
        "#,
        &["16 262144"],
        1_048_576,
        false,
    );
}

#[test]
fn live_reads_and_replacement_conversion_order_are_preserved() {
    check(
        r#"
        const source = new Int16Array([1, 2, 3]);
        const copy = source.with(1, { valueOf() { source[0] = 9; return 7; } });
        console.log(copy.join(','), source.join(','));
        const filtered = source.filter(function(value, index) {
          if (index === 0) source[1] = 8;
          return true;
        });
        console.log(filtered.join(','));
        try { new BigInt64Array([1n]).with(5, 2); }
        catch (error) { console.log(error.name); }
        "#,
        &["9,7,3 9,2,3", "9,8,3", "TypeError"],
        1_048_576,
        false,
    );
}

#[test]
fn iterable_constructor_finishes_iteration_before_converting_values() {
    check(
        r#"
        const events = [];
        const source = { *[Symbol.iterator]() {
          events.push('yield1');
          yield { valueOf() { events.push('value1'); return 2; } };
          events.push('yield2');
          yield { valueOf() { events.push('value2'); return 3; } };
          events.push('done');
        }};
        const copy = new Int8Array(source);
        console.log(events.join(','), copy.join(','));
        "#,
        &["yield1,yield2,done,value1,value2 2,3"],
        1_048_576,
        false,
    );
}

#[test]
fn typed_array_from_mapper_allocations_include_the_collected_source() {
    let slots = 4096 * std::mem::size_of::<Value>() as u64;
    let allocation = 262_144 + slots;
    for constructor in [
        "Uint8Array",
        "function(length) { return new Uint8Array(length); }",
    ] {
        let source = format!(
            "let held; const result = Uint8Array.from.call({constructor}, new Uint8Array(4096), function(value, index) {{ if (index === 0) {{ console.log('mapper'); held = new Uint8Array({allocation}); }} return value; }}); console.log(result.length);"
        );
        // The managed source, collected native list, and mapper allocation
        // must share one ceiling, including for a custom destination.
        check(&source, &["mapper"], 262_144 + 3 * slots, true);
        check(&source, &["mapper", "4096"], 16_777_216, false);
    }
}

#[test]
fn typed_array_from_streams_large_mapper_payloads_into_the_destination() {
    check(
        r#"
        const result = Uint8Array.from({ length: 128 }, function() {
          return '0'.repeat(16384);
        });
        console.log(result.length, result[0], result[127]);
        console.log(BigInt64Array.of(true, '2', 3n).join(','));
        console.log(Uint8Array.of().length, Uint8Array.from([]).length);
        "#,
        &["128 0 0", "1,2,3", "0 0"],
        524_288,
        false,
    );
}

#[test]
fn typed_array_static_calls_convert_and_write_before_the_next_element() {
    check(
        r#"
        const events = [];
        const target = new Uint8Array(3);
        function Destination(length) { events.push('ctor:' + length); return target; }
        try {
          Uint8Array.from.call(Destination, [3, 4, 5], function(value, index) {
            events.push('map:' + index + ':' + target[0]);
            return { valueOf() {
              events.push('value:' + index);
              if (index === 1) throw Error('stop');
              return value + 10;
            }};
          });
        } catch (error) { console.log(error.message); }
        console.log(events.join(','), target.join(','));
        events.length = 0;
        target[0] = 0;
        const first = { valueOf() { events.push('first'); return 7; } };
        const second = { valueOf() { events.push('second:' + target[0]); return 9; } };
        const result = Uint8Array.of.call(Destination, first, second);
        console.log(result === target, events.join(','), target.join(','));
        "#,
        &[
            "stop",
            "ctor:3,map:0:0,value:0,map:1:13,value:1 13,0,0",
            "true ctor:2,first,second:7 7,9,0",
        ],
        1_048_576,
        false,
    );
}

#[test]
fn typed_array_from_keeps_iterator_and_mapper_validation_order() {
    check(
        r#"
        let reads = 0;
        const untouched = { get [Symbol.iterator]() { reads++; throw Error('read'); } };
        try { Uint8Array.from(untouched, 7); }
        catch (error) { console.log(error.name, reads); }
        const events = [];
        const source = { *[Symbol.iterator]() {
          events.push('yield1'); yield 1;
          events.push('yield2'); yield 2;
          events.push('done');
        }};
        const result = Uint8Array.from(source, function(value, index) {
          events.push('map' + index);
          return value + 1;
        });
        console.log(events.join(','), result.join(','));
        "#,
        &["TypeError 0", "yield1,yield2,done,map0,map1 2,3"],
        1_048_576,
        false,
    );
}

#[test]
fn typed_array_static_calls_release_sources_after_abrupt_completion() {
    check(
        r#"
        const source = new Uint8Array(128);
        const bad = { valueOf() { throw Error('conversion'); } };
        let caught = 0;
        for (let round = 0; round < 32; round++) {
          try {
            Uint8Array.from(source, function() {
              if (round % 2 === 0) throw Error('mapper');
              return bad;
            });
          } catch (error) { caught++; }
          try { Uint8Array.of(bad, 1, 2, 3); }
          catch (error) { caught++; }
        }
        console.log(caught, new Uint8Array(655360).length);
        "#,
        &["64 655360"],
        1_048_576,
        false,
    );
}

#[test]
fn ordinary_array_sort_converts_comparator_objects_and_rejects_bigint() {
    check(
        r#"
        const source = [3, 1, 2];
        source.sort(function(a, b) { return { valueOf() { return a - b; } }; });
        console.log(source.join(','));
        const unchanged = [3, 1, 2];
        try { unchanged.sort(function() { return 1n; }); }
        catch (error) { console.log(error.name, unchanged.join(',')); }
        "#,
        &["1,2,3", "TypeError 3,1,2"],
        1_048_576,
        false,
    );
}

const TYPED_ARRAY_JOIN_LARGE_SEPARATOR: &str = r#"
const source = new Uint8Array(4096);
const separator = { toString() { console.log('separator'); return 'x'.repeat(1024); } };
console.log('joining');
const joined = source.join(separator);
console.log(joined.length);
"#;

#[test]
fn typed_array_join_refuses_growth_before_materializing_an_oversized_result() {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "typed-array-join-memory.js".into(),
                text: TYPED_ARRAY_JOIN_LARGE_SEPARATOR.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("join fixture parses");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "typed-array-join-memory.js"),
        &LoweringContext::new("typed-array-join-memory", "native", "builtin-only"),
    )
    .expect("join fixture lowers")
    .ir3;
    for v8_profile in [false, true] {
        let mut config = if v8_profile {
            InterpreterConfig::v8_defaults()
        } else {
            InterpreterConfig::quickjs_defaults()
        };
        config.instruction_budget = 10_000_000;
        config.max_registers = 256;
        config.max_total_memory_bytes = 524_288;
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
            RuntimeCapability::Console,
        ]
        .into_iter()
        .collect();
        let mut core = InterpreterCore::new(config, "typed-array-join-memory");
        match core.execute(&module).expect_err("large join exceeds the budget") {
            InterpreterError::MemoryBudgetExceeded {
                requested_bytes,
                max_bytes,
                ..
            } => {
                assert_eq!(max_bytes, 524_288);
                assert!(requested_bytes > max_bytes);
                // The old implementation first materialized over 4 MiB, then
                // refused publication. Geometric admission must fail while
                // requesting at most one further budget-sized allocation.
                assert!(
                    requested_bytes <= max_bytes.saturating_mul(2),
                    "late join refusal: requested {requested_bytes} (v8={v8_profile})"
                );
            }
            error => panic!("unexpected join failure (v8={v8_profile}): {error}"),
        }
        assert_eq!(
            core.console_output()
                .iter()
                .map(|entry| entry.message.as_str())
                .collect::<Vec<_>>(),
            ["joining", "separator"],
            "separator coercion precedes the memory refusal (v8={v8_profile})"
        );
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes(),
            "join accounting after refusal (v8={v8_profile})"
        );
    }
    check(
        TYPED_ARRAY_JOIN_LARGE_SEPARATOR,
        &["joining", "separator", "4197376"],
        16_777_216,
        false,
    );
}

#[test]
fn typed_array_join_keeps_exact_surrogates_across_separator_boundaries() {
    check(
        r#"
        const values = new Uint8Array([1, 2, 3]);
        const lone = values.join('\uD800');
        console.log(lone.length, lone.charCodeAt(1), lone.charCodeAt(3));
        const astral = values.join('😀');
        console.log(astral.length, astral.charCodeAt(1), astral.charCodeAt(2), astral[3]);
        const buffer = new ArrayBuffer(4, { maxByteLength: 8 });
        const shrinking = new Uint8Array(buffer);
        const healed = shrinking.join({ toString() { buffer.resize(0); return '\uDC00\uD800'; } });
        console.log(healed.length, healed.charCodeAt(0), healed.charCodeAt(1), healed.charCodeAt(2), healed.charCodeAt(5));
        console.log(healed.slice(1, 3) === '\uD800\uDC00');
        "#,
        &[
            "5 55296 55296",
            "7 55357 56832 2",
            "6 56320 55296 56320 55296",
            "true",
        ],
        1_048_576,
        false,
    );
}

#[test]
fn typed_array_join_preserves_separator_coercion_and_live_resized_reads() {
    check(
        r#"
        const buffer = new ArrayBuffer(6, { maxByteLength: 12 });
        const view = new Uint8Array(buffer, 2);
        view.set([1, 2, 3, 4]);
        let conversions = 0;
        const joined = view.join({ toString() { conversions++; view[0] = 9; buffer.resize(4); return '|'; } });
        console.log(conversions, joined, view.length);
        const growingBuffer = new ArrayBuffer(2, { maxByteLength: 8 });
        const growing = new Uint8Array(growingBuffer);
        growing.set([1, 2]);
        console.log(growing.join({ toString() { growingBuffer.resize(4); growing[2] = 3; return '|'; } }), growing.length);
        const empty = new Uint8Array(0);
        console.log(empty.join({ toString() { conversions++; return ';'; } }) === '', conversions);
        try { empty.join(Symbol('separator')); } catch (error) { console.log(error.name); }
        console.log(new BigInt64Array([1n, -2n]).join(123n));
        "#,
        &["1 9|2|| 2", "1|2 4", "true 2", "TypeError", "1123-2"],
        1_048_576,
        false,
    );
}

#[test]
fn typed_array_join_releases_output_and_coerced_separator_between_calls() {
    check(
        r#"
        const source = new Uint8Array(2);
        const separator = { toString() { return 'x'.repeat(16384); } };
        let length = 0;
        for (let index = 0; index < 64; index++) length = source.join(separator).length;
        console.log(length, new Uint8Array(262144).length);
        "#,
        &["16386 262144"],
        524_288,
        false,
    );
}
