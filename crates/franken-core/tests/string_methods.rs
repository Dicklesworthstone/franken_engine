//! Native string methods exercised through parse -> lowering -> both profiles.

use std::collections::BTreeSet;

use frankenengine_core::ast::ParseGoal;
use frankenengine_core::baseline_interpreter::{
    ExecutionSeed, InterpreterConfig, InterpreterCore, InterpreterError, Value,
};
use frankenengine_core::capability::RuntimeCapability;
use frankenengine_core::hash_tiers::ContentHash;
use frankenengine_core::ifc_artifacts::Label;
use frankenengine_core::ir_contract::{Ir0Module, Ir3Instruction as Op, Ir3Module, RegRange};
use frankenengine_core::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_core::parser::{CanonicalEs2020Parser, Es2020Parser};

fn lower(source: &str) -> Ir3Module {
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Module)
        .expect("parse");
    lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "string-methods.mjs"),
        &LoweringContext::new("strings", "strings", "strings"),
    )
    .expect("lower")
    .ir3
}

fn config(throughput: bool) -> InterpreterConfig {
    let mut config = if throughput {
        InterpreterConfig::v8_defaults()
    } else {
        InterpreterConfig::quickjs_defaults()
    };
    config.granted_capabilities = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
    ]);
    config
}

fn assert_output(source: &str, expected: &[&str]) {
    let module = lower(source);
    for throughput in [false, true] {
        let mut execution_config = config(throughput);
        // These source scenarios deliberately group many independent calls;
        // lowering assigns temporaries for the complete module frame.
        execution_config.max_registers = 1024;
        let output = InterpreterCore::new(execution_config, "strings")
            .execute(&module)
            .unwrap_or_else(|error| panic!("{source}: {error:?}"));
        let lines: Vec<_> = output
            .console_output
            .into_iter()
            .map(|line| line.message)
            .collect();
        assert_eq!(lines, expected, "throughput={throughput}: {source}");
    }
}

#[test]
fn search_and_slicing_cover_default_negative_fractional_and_infinite_positions() {
    assert_output(
        r#"
        const s = 'banana';
        console.log(s.indexOf('na'));
        console.log(s.indexOf('na', 3));
        console.log(s.lastIndexOf('na'));
        console.log(s.lastIndexOf('na', 3));
        console.log(s.lastIndexOf('a', undefined));
        console.log(s.lastIndexOf('a', NaN));
        console.log(s.lastIndexOf('a', null));
        console.log(s.indexOf('', Infinity));
        console.log(s.lastIndexOf('', -Infinity));
        console.log(s.includes('ana', 2));
        console.log(s.startsWith('ana', 1));
        console.log(s.endsWith('ana', 4));
        console.log(s.endsWith('ana', undefined));
        console.log(s.startsWith('', Infinity));
        console.log(s.endsWith('', -Infinity));
        console.log(s.includes('b', Infinity));
        console.log('undefined'.indexOf());
        console.log('undefined'.endsWith());
        console.log('abcdef'.slice(2, -1));
        console.log('abcdef'.slice(-3.8, -1.2));
        console.log('abcdef'.slice(4, 2));
        console.log('abcdef'.substring(4, 2));
        console.log('abcdef'.substring(-1, 2));
        console.log('abcdef'.slice(-Infinity, Infinity));
        console.log('abcdef'.substring(NaN, undefined));
    "#,
        &[
            "2", "4", "4", "2", "5", "5", "-1", "6", "0", "true", "true", "true", "true", "true",
            "true", "false", "0", "true", "cde", "de", "", "cd", "ab", "abcdef", "abcdef",
        ],
    );
}

#[test]
fn positions_use_javascript_numeric_strings_and_whitespace() {
    assert_output(
        r#"
        console.log('abcabc'.indexOf('a', '0x1'));
        console.log('abcabc'.indexOf('a', '0b10'));
        console.log('abcabc'.indexOf('a', '0o3'));
        console.log('abcabc'.indexOf('a', '+0x1'));
        console.log('abcabc'.indexOf('a', '1e0'));
        console.log('abcabc'.indexOf('a', '1e'));
        console.log('abc'.startsWith('a', 'inf'));
        console.log('abc'.startsWith('a', 'infinity'));
        console.log('abc'.startsWith('b', '\uFEFF1\u00A0'));
        console.log('abc'.startsWith('a', '\u00851'));
        console.log('abc'.startsWith('a', '\uD800'));
        console.log('abcabc'.lastIndexOf('a', 'not a number'));
        console.log('abcdef'.slice('0x2', '0b101'));
        console.log('abcdef'.substring('3.9', '1.2'));
    "#,
        &[
            "3", "3", "3", "0", "3", "0", "true", "true", "true", "true", "true", "3", "cde", "bc",
        ],
    );
}

#[test]
fn utf16_search_and_slices_preserve_surrogates_and_rope_boundaries() {
    assert_output(
        r#"
        const s = 'A\uD83D\uDE00B\uD800C\uDC00D';
        console.log(s.length);
        console.log(s.indexOf('\uD83D\uDE00'));
        console.log(s.indexOf('\uDE00', 2));
        console.log(s.lastIndexOf('\uD800'));
        console.log(s.includes('\uDC00'));
        console.log(s.startsWith('\uDE00B', 2));
        console.log(s.endsWith('\uD800', 5));
        console.log(s.slice(1, 2) === '\uD83D');
        console.log(s.substring(3, 2) === '\uDE00');
        console.log(s.slice(-2, -1) === '\uDC00');
        console.log(s.slice(1, 3) === '\uD83D\uDE00');
        const rope = ('left' + '\uD83D') + ('\uDE00' + 'right');
        console.log(rope.indexOf('\uD83D\uDE00'));
        console.log(rope.lastIndexOf('right'));
        console.log(rope.slice(4, 5) === '\uD83D');
        console.log(rope.substring(5, 6) === '\uDE00');
    "#,
        &[
            "8", "1", "2", "4", "true", "true", "true", "true", "true", "true", "true", "4", "6",
            "true", "true",
        ],
    );
}

#[test]
fn borrowed_methods_observe_receiver_search_and_position_coercion_in_order() {
    assert_output(
        r#"
        const receiver = {
            includes: ''.includes,
            slice: ''.slice,
            toString() { console.log('receiver'); return 'abcdef'; }
        };
        const search = {
            get [Symbol.match]() { console.log('match'); return false; },
            toString() { console.log('search'); return 'cd'; }
        };
        const position = { valueOf() { console.log('position'); return 2; } };
        console.log(receiver.includes(search, position));
        const start = { [Symbol.toPrimitive](hint) { console.log('start:' + hint); return 1; } };
        const end = { valueOf() { console.log('end'); return 4; } };
        console.log(receiver.slice(start, end));
        const primitive = { indexOf: ''.indexOf, [Symbol.toPrimitive](hint) { console.log(hint); return 12345; } };
        console.log(primitive.indexOf(34));
        const detached = ''.indexOf;
        try { detached('x'); } catch (error) { console.log(error.name); }
    "#,
        &[
            "receiver",
            "match",
            "search",
            "position",
            "true",
            "receiver",
            "start:number",
            "end",
            "bcd",
            "string",
            "2",
            "TypeError",
        ],
    );
}

#[test]
fn regexp_detection_and_abrupt_completions_do_not_run_later_coercions() {
    assert_output(
        r#"
        const regexpLike = {
            get [Symbol.match]() { console.log('regexp'); return true; },
            toString() { console.log('stringify'); return 'x'; }
        };
        const position = { valueOf() { console.log('unreachable'); return 0; } };
        try { 'x'.includes(regexpLike, position); } catch (error) { console.log(error.name); }
        try { 'x'.startsWith(regexpLike, position); } catch (error) { console.log(error.name); }
        try { 'x'.endsWith(regexpLike, position); } catch (error) { console.log(error.name); }
        console.log('x'.indexOf(regexpLike));
        const marker = { tag: 'exact exception' };
        const throwing = { get [Symbol.match]() { throw marker; } };
        try { 'x'.includes(throwing, position); } catch (error) { console.log(error === marker); }
        const receiver = { slice: ''.slice, toString() { throw marker; } };
        try { receiver.slice(position); } catch (error) { console.log(error === marker); }
        try { 'abc'.slice(Symbol('start')); } catch (error) { console.log(error.name); }
        try { 'abc'.includes(Symbol('search')); } catch (error) { console.log(error.name); }
        try { 'abc'.lastIndexOf('a', Symbol('position')); } catch (error) { console.log(error.name); }
    "#,
        &[
            "regexp",
            "TypeError",
            "regexp",
            "TypeError",
            "regexp",
            "TypeError",
            "stringify",
            "0",
            "true",
            "true",
            "TypeError",
            "TypeError",
            "TypeError",
        ],
    );
}

#[test]
fn native_scans_consume_instruction_budget_before_searching() {
    let source = format!("'{}'.indexOf('z');", "a".repeat(4096));
    let module = lower(&source);
    for throughput in [false, true] {
        let mut config = config(throughput);
        config.instruction_budget = 100;
        let error = InterpreterCore::new(config, "string-budget")
            .execute(&module)
            .unwrap_err();
        assert!(
            matches!(error, InterpreterError::BudgetExhausted { .. }),
            "{error:?}"
        );
    }
}

#[test]
fn search_and_slice_results_retain_receiver_argument_and_position_provenance() {
    let mut module = Ir3Module::new(ContentHash::compute(b"string-labels"), "string-labels");
    module.instructions = vec![
        Op::GetProperty {
            dst: 4,
            obj: 0,
            key: 1,
        },
        Op::CallMethod {
            dst: 5,
            callee: 4,
            receiver: 0,
            args: RegRange { start: 2, count: 2 },
        },
        Op::Return { value: 5 },
    ];
    for throughput in [false, true] {
        for secret_register in [0, 2, 3] {
            for (method, first, second, expected) in [
                ("indexOf", Value::str("bc"), Value::Int(0), Value::Int(1)),
                (
                    "lastIndexOf",
                    Value::str("bc"),
                    Value::Int(6),
                    Value::Int(4),
                ),
                (
                    "includes",
                    Value::str("bc"),
                    Value::Int(0),
                    Value::Bool(true),
                ),
                (
                    "startsWith",
                    Value::str("bc"),
                    Value::Int(1),
                    Value::Bool(true),
                ),
                (
                    "endsWith",
                    Value::str("bc"),
                    Value::Int(3),
                    Value::Bool(true),
                ),
                ("slice", Value::Int(1), Value::Int(3), Value::str("bc")),
                ("substring", Value::Int(3), Value::Int(1), Value::str("bc")),
            ] {
                let mut core = InterpreterCore::new(config(throughput), "string-labels");
                core.write_register(0, Value::str("abcabc"));
                core.write_register(1, Value::str(method));
                core.write_register(2, first);
                core.write_register(3, second);
                let mut wire = serde_json::to_value(core.capture_execution_seed()).unwrap();
                wire["register_labels"][secret_register] =
                    serde_json::to_value(Label::Secret).unwrap();
                let seed: ExecutionSeed = serde_json::from_value(wire).unwrap();
                core.reset_execution_state_from_seed(&seed).unwrap();
                let result = core.execute(&module).unwrap();
                assert_eq!(result.value, expected, "{method}");
                assert_eq!(
                    result.completion_label,
                    Label::Secret,
                    "{method}, secret r{secret_register}"
                );
            }
        }
    }
}

#[test]
fn native_string_type_errors_keep_secret_dependencies_in_catch() {
    use frankenengine_core::baseline_interpreter::ObjectId;
    use frankenengine_core::object_model::WellKnownSymbol;

    const SECRET_REGISTER: u32 = 255;
    for throughput in [false, true] {
        for (invocation, secret) in [
            (
                "'abc'.includes(secret)",
                Value::Symbol(WellKnownSymbol::Iterator.id()),
            ),
            (
                "'abc'.slice(secret)",
                Value::Symbol(WellKnownSymbol::Iterator.id()),
            ),
            (
                "'abc'.indexOf('a', secret)",
                Value::Symbol(WellKnownSymbol::Iterator.id()),
            ),
            (
                "'abc'.includes({ get [Symbol.match]() { return secret; } })",
                Value::Bool(true),
            ),
            (
                "'abc'.slice({ [Symbol.toPrimitive]() { return secret; } })",
                Value::Object(ObjectId(0)),
            ),
        ] {
            let mut core = InterpreterCore::new(config(throughput), "string-error-labels");
            if matches!(secret, Value::Object(_)) {
                core.write_heap_slot(0, Value::Undefined);
            }
            let mut module = lower(&format!(
                "const secret = 424242; let result = ''; try {{ {invocation}; }} catch (error) {{ result = error.name; }} result;"
            ));
            // Restore only data before creating the coercion closures: public
            // seeds deliberately omit their executable module ownership.
            let mut injected = 0;
            for instruction in &mut module.instructions {
                if let Op::LoadInt { dst, value: 424242 } = instruction {
                    *instruction = Op::Move {
                        dst: *dst,
                        src: SECRET_REGISTER,
                    };
                    injected += 1;
                }
            }
            assert_eq!(injected, 1, "one source binding receives the secret value");
            core.write_register(SECRET_REGISTER as usize, secret);
            let mut wire = serde_json::to_value(core.capture_execution_seed()).unwrap();
            wire["register_labels"][SECRET_REGISTER as usize] =
                serde_json::to_value(Label::Secret).unwrap();
            core.reset_execution_state_from_seed(
                &serde_json::from_value::<ExecutionSeed>(wire).unwrap(),
            )
            .unwrap();
            let result = core.execute(&module).unwrap();
            assert_eq!(result.value, Value::str("TypeError"), "{invocation}");
            assert_eq!(result.completion_label, Label::Secret, "{invocation}");
        }
    }
}

#[test]
fn multibyte_rope_search_admits_byte_sized_failure_tables_before_matching() {
    use frankenengine_core::js_string::JsString;

    let mut module = Ir3Module::new(
        ContentHash::compute(b"string-search-memory"),
        "string-search-memory",
    );
    module.instructions = vec![
        Op::GetProperty {
            dst: 4,
            obj: 0,
            key: 1,
        },
        Op::CallMethod {
            dst: 5,
            callee: 4,
            receiver: 0,
            args: RegRange { start: 2, count: 1 },
        },
        Op::Return { value: 5 },
    ];
    let inputs = || {
        let leaf = JsString::from("界".repeat(2048));
        let receiver = leaf.concat(&leaf);
        let prefix = JsString::from("界".repeat(512));
        let needle = prefix.concat(&JsString::from("文")).concat(&prefix);
        assert!(receiver.concat_parts().nodes > 0);
        assert!(needle.concat_parts().nodes > 0);
        (receiver, needle)
    };
    for throughput in [false, true] {
        for method in ["indexOf", "lastIndexOf"] {
            let (receiver, needle) = inputs();
            // Native locals retain both strings during search. Admit those
            // copies, but leave less room than the byte-indexed failure table
            // needs. Scale its size with the platform's native table entries.
            let retained_inputs = receiver.retained_bytes(0) + needle.retained_bytes(0);
            let scratch_headroom = (needle.len() as u64)
                .saturating_mul(std::mem::size_of::<usize>() as u64)
                .saturating_sub(4096);
            let mut generous = InterpreterCore::new(config(throughput), "string-search-memory");
            generous.write_register(0, Value::Str(receiver));
            generous.write_register(1, Value::str(method));
            generous.write_register(2, Value::Str(needle));
            assert_eq!(generous.execute(&module).unwrap().value, Value::Int(-1));

            let mut bounded_config = config(throughput);
            bounded_config.max_total_memory_bytes =
                generous.estimated_memory_bytes() + retained_inputs + scratch_headroom;
            let mut bounded = InterpreterCore::new(bounded_config, "string-search-memory");
            // Fresh direct register writes preserve the unjoined rope. A
            // serialized ExecutionSeed would flatten it and miss this path.
            let (receiver, needle) = inputs();
            bounded.write_register(0, Value::Str(receiver));
            bounded.write_register(1, Value::str(method));
            bounded.write_register(2, Value::Str(needle));
            let error = bounded.execute(&module).unwrap_err();
            assert!(
                matches!(error, InterpreterError::MemoryBudgetExceeded { .. }),
                "{method}, throughput={throughput}: {error:?}",
            );
        }
    }
}
