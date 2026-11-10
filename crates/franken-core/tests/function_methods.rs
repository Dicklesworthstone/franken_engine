//! Callable call/apply use the normal invocation, ownership and budget paths.

use std::collections::BTreeSet;
use std::path::PathBuf;

use frankenengine_core::ast::ParseGoal;
use frankenengine_core::baseline_interpreter::{
    ExecutionSeed, InterpreterConfig, InterpreterCore, InterpreterError, Value,
};
use frankenengine_core::capability::RuntimeCapability;
use frankenengine_core::hash_tiers::ContentHash;
use frankenengine_core::ifc_artifacts::Label;
use frankenengine_core::ir_contract::{Ir0Module, Ir3Instruction as Op, Ir3Module};
use frankenengine_core::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_core::parser::{CanonicalEs2020Parser, Es2020Parser};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/modules")
}

fn lower(source: &str) -> Ir3Module {
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Module)
        .expect("parse");
    lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(
            tree,
            fixture_root()
                .join("function-methods.mjs")
                .display()
                .to_string(),
        ),
        &LoweringContext::new("function-methods", "function-methods", "function-methods"),
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
    config.max_registers = 1024;
    config.module_root = Some(fixture_root().display().to_string());
    config.granted_capabilities = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::ModuleLoad,
    ]);
    config
}

fn assert_output(source: &str, expected: &[&str]) {
    let module = lower(source);
    for throughput in [false, true] {
        let result = InterpreterCore::new(config(throughput), "function-methods")
            .execute(&module)
            .unwrap_or_else(|error| panic!("{source}: {error:?}"));
        let actual: Vec<_> = result
            .console_output
            .into_iter()
            .map(|line| line.message)
            .collect();
        assert_eq!(actual, expected, "throughput={throughput}: {source}");
    }
}

#[test]
fn call_and_apply_forward_receivers_arguments_and_borrowed_builtins() {
    assert_output(
        r#"
        function describe(a, b, c) { return this.tag + ':' + a + ':' + b + ':' + c; }
        console.log(describe.call({ tag: 'call' }, 1, 2, 3));
        console.log(describe.apply({ tag: 'apply' }, [4, 5, 6]));
        function identity() { return this; }
        console.log(identity.call() === undefined);
        console.log(identity.call(null) === null);
        console.log(identity.apply(7, null));
        console.log(identity.apply(8, undefined));
        function first(value) { return value; }
        console.log(first.apply(null));
        console.log(first.call(null, 9, 10));
        console.log(''.slice.call('abcdef', 1, -1));
        console.log(''.includes.apply('banana', ['na', 3]));
        const arrayLike = { 0: 'a', length: 1 };
        console.log([].push.call(arrayLike, 'b', 'c'));
        console.log([].join.apply(arrayLike, ['|']));
        console.log(Array.isArray.call(null, []));
        console.log(first.call === identity.call);
        console.log(first.apply === identity.apply);
        console.log(first.call.prototype, first.apply.prototype);
    "#,
        &[
            "call:1:2:3",
            "apply:4:5:6",
            "true",
            "true",
            "7",
            "8",
            "undefined",
            "9",
            "bcde",
            "true",
            "3",
            "a|b|c",
            "true",
            "true",
            "true",
            "undefined undefined",
        ],
    );
}

#[test]
fn apply_snapshots_length_then_reads_live_inherited_and_missing_elements() {
    assert_output(
        r#"
        function report(a, b, c, d) { console.log(a + ':' + b + ':' + c + ':' + d); }
        const proto = { get 2() { console.log('inherited'); return 'c'; } };
        const list = {
            __proto__: proto,
            get length() {
                console.log('length');
                return { valueOf() { console.log('convert'); return 4.8; } };
            },
            get 0() { console.log('first'); this[1] = 'updated'; return 'a'; },
            1: 'old'
        };
        report.apply(null, list);
        report.apply(null, [, 2, , 4]);
        report.apply(null, { length: '0x2', 0: 5, 1: 6 });
        report.apply(null, { length: -1, get 0() { throw 'unreachable'; } });
        report.apply(null, { length: NaN });
    "#,
        &[
            "length",
            "convert",
            "first",
            "inherited",
            "a:updated:c:undefined",
            "undefined:2:undefined:4",
            "5:6:undefined:undefined",
            "undefined:undefined:undefined:undefined",
            "undefined:undefined:undefined:undefined",
        ],
    );
}

#[test]
fn validation_order_and_abrupt_completions_are_observable_and_catchable() {
    assert_output(
        r#"
        function identity(value) { return value; }
        const badReceiver = { apply: identity.apply };
        try { badReceiver.apply(null, { get length() { console.log('unreachable'); return 0; } }); }
        catch (error) { console.log(error.name); }
        for (const primitive of [1, true, 'abc', Symbol('list')]) {
            try { identity.apply(null, primitive); } catch (error) { console.log(error.name); }
        }
        const detached = identity.call;
        try { detached(); } catch (error) { console.log(error.name); }
        const token = {};
        try { identity.apply(null, { get length() { throw token; } }); }
        catch (error) { console.log(error === token); }
        try { identity.apply(null, { length: 2, get 0() { throw token; }, get 1() { console.log('unreachable'); } }); }
        catch (error) { console.log(error === token); }
        function fail() { try { throw token; } finally { console.log('callee finally'); } }
        try { try { fail.call(null); } finally { console.log('caller finally'); } }
        catch (error) { console.log(error === token); }
        console.log(identity.apply(null, [42]));
    "#,
        &[
            "TypeError",
            "TypeError",
            "TypeError",
            "TypeError",
            "TypeError",
            "TypeError",
            "true",
            "true",
            "callee finally",
            "caller finally",
            "true",
            "42",
        ],
    );
}

#[test]
fn methods_remain_first_class_and_respect_property_overrides_and_prototypes() {
    assert_output(
        r#"
        function add(a, b) { return a + b; }
        const call = add.call;
        const apply = add.apply;
        console.log('call' in add, 'apply' in add, Object.keys(add).length);
        console.log(call.call(add, null, 2, 3));
        console.log(apply.call(add, null, [4, 5]));
        add.call = function(value) { return 'own:' + value; };
        console.log(add.call(6));
        console.log(call.call(add, null, 7, 8));
        delete add.call;
        console.log('call' in add);
        console.log(add.call(null, 9, 10));
        add.__proto__ = { apply: function() { return 'prototype'; } };
        console.log(add.apply());
        console.log(add.call);
        console.log('call' in add, 'apply' in add);
        add.__proto__ = null;
        console.log(add.apply);
        console.log('call' in add, 'apply' in add);
        console.log(apply.call(add, null, [11, 12]));
    "#,
        &[
            "true true 0",
            "5",
            "9",
            "own:6",
            "15",
            "true",
            "19",
            "prototype",
            "undefined",
            "false true",
            "undefined",
            "false false",
            "23",
        ],
    );
}

#[test]
fn imported_closures_generators_and_async_functions_keep_their_owners() {
    assert_output(
        r#"
        import { add, apply, fail, values, makeCounter, resolved } from './operations.mjs';
        import { delayed } from './async_operations.mjs';
        function unrelated() { return -900; }
        console.log(add.call(null, 2));
        console.log(apply.apply(null, [value => value * 2, 5]));
        const counter = makeCounter();
        console.log(counter.call(null));
        console.log(counter.apply(null, []));
        const iterator = values.call(null, 3);
        console.log(iterator.next().value);
        console.log(iterator.next.apply(iterator, []).value);
        console.log(iterator.next.call(iterator).value);
        try { fail.apply(null, []); } catch (error) { console.log(error); }
        resolved.call(null, 4).then(value => console.log('resolved:' + value));
        delayed.apply(null, [8]).then(value => console.log('delayed:' + value));
        console.log('sync');
    "#,
        &[
            "42",
            "11",
            "1",
            "2",
            "3",
            "43",
            "99",
            "17",
            "sync",
            "resolved:44",
            "delayed:9",
        ],
    );
}

#[test]
fn async_generator_and_promise_builtins_use_the_same_method_path() {
    assert_output(
        r#"
        import { importedValues } from './async_generators.mjs';
        const iterator = importedValues.apply(null, [6]);
        iterator.next.call(iterator).then(result => console.log(result.value));
        iterator.next.apply(iterator, []).then(result => console.log(result.value + ':' + result.done));
        const promise = new Promise(resolve => { resolve.call(null, 42); });
        promise.then.call(promise, value => console.log('promise:' + value));
        console.log('sync');
    "#,
        &["sync", "promise:42", "owner:7", "8:true"],
    );
}

#[test]
fn apply_bounds_arguments_before_reads_and_native_recursion_stays_bounded() {
    let oversized = lower(
        r#"
        function target() { console.log('called'); }
        try { target.apply(null, { length: 1000000000, get 0() { console.log('read'); return 1; } }); }
        catch (error) { console.log('caught'); }
    "#,
    );
    let recursive = lower(
        r#"
        const apply = (function() {}).apply;
        const argumentsList = [apply, null];
        argumentsList[1] = argumentsList;
        try { apply.apply(apply, argumentsList); } catch (error) { console.log('caught'); }
    "#,
    );
    for throughput in [false, true] {
        let mut core = InterpreterCore::new(config(throughput), "apply-oversized");
        assert!(matches!(
            core.execute(&oversized),
            Err(InterpreterError::RegisterOutOfBounds { .. })
        ));
        let mut bounded = config(throughput);
        bounded.max_call_depth = 12;
        let mut core = InterpreterCore::new(bounded, "apply-recursive");
        assert!(matches!(
            core.execute(&recursive),
            Err(InterpreterError::StackOverflow { .. })
        ));
        assert_eq!(
            core.execute(&lower("41 + 1;")).unwrap().value,
            Value::Int(42)
        );
    }
}

#[test]
fn callable_methods_preserve_argument_receiver_and_result_labels() {
    for throughput in [false, true] {
        for source in [
            "function identity(value) { return value; } identity.call(null, 42);",
            "function identity(value) { return value; } identity.apply(null, [42]);",
            "function identity() { return this; } identity.call(42);",
            "function ignore() { return 1; } ignore.apply(null, [42]);",
            "let saved; function write(value) { saved = value; } write.call(null, 42); saved;",
            "function f() {} let caught; try { f.apply(null, 42); } catch (error) { caught = error; } caught;",
            "function f() { return 1; } f[42] = f.call; const selected = f[42]; const target = { method: selected }; let caught; try { target.method(null); } catch (error) { caught = error; } caught;",
        ] {
            let mut module = lower(source);
            const SECRET_REGISTER: u32 = 1023;
            let mut count = 0;
            for instruction in &mut module.instructions {
                if let Op::LoadInt { dst, value: 42 } = instruction {
                    *instruction = Op::Move {
                        dst: *dst,
                        src: SECRET_REGISTER,
                    };
                    count += 1;
                }
            }
            assert_eq!(count, if source.contains("f[42]") { 2 } else { 1 });
            let mut core = InterpreterCore::new(config(throughput), "function-method-labels");
            core.write_register(SECRET_REGISTER as usize, Value::Int(42));
            let mut wire = serde_json::to_value(core.capture_execution_seed()).unwrap();
            wire["register_labels"][SECRET_REGISTER as usize] =
                serde_json::to_value(Label::Secret).unwrap();
            core.reset_execution_state_from_seed(
                &serde_json::from_value::<ExecutionSeed>(wire).unwrap(),
            )
            .unwrap();
            assert_eq!(
                core.execute(&module).unwrap().completion_label,
                Label::Secret,
                "{source}"
            );
        }
    }
}

#[test]
fn explicit_null_function_prototype_survives_seed_roundtrip_and_reset() {
    for throughput in [false, true] {
        let mut core = InterpreterCore::new(config(throughput), "function-null-seed");
        let empty = core.capture_execution_seed();
        let function = core
            .execute(&lower("function f() {} f.__proto__ = null; f;"))
            .unwrap()
            .value;
        core.write_register(0, function);
        core.write_register(1, Value::str("call"));
        let wire = serde_json::to_value(core.capture_execution_seed()).unwrap();
        assert_eq!(
            wire["function_null_prototypes"].as_array().unwrap().len(),
            1
        );
        let seed = serde_json::from_value::<ExecutionSeed>(wire.clone()).unwrap();
        let mut lookup = Ir3Module::new(
            ContentHash::compute(b"function-null-lookup"),
            "function-null-lookup",
        );
        lookup.instructions = vec![
            Op::GetProperty {
                obj: 0,
                key: 1,
                dst: 2,
            },
            Op::Return { value: 2 },
        ];
        let mut restored = InterpreterCore::new(config(throughput), "restored-function-null");
        restored.reset_execution_state_from_seed(&seed).unwrap();
        assert_eq!(restored.execute(&lookup).unwrap().value, Value::Undefined);
        let eager = core.capture_execution_seed_eager_for_test();
        let mut restored_eager =
            InterpreterCore::new(config(throughput), "restored-eager-function-null");
        restored_eager
            .reset_execution_state_from_seed_eager_for_test(&eager)
            .unwrap();
        assert_eq!(
            restored_eager.execute(&lookup).unwrap().value,
            Value::Undefined
        );
        let mut invalid = wire;
        invalid["function_null_prototypes"] = serde_json::json!([999999]);
        assert!(serde_json::from_value::<ExecutionSeed>(invalid).is_err());
        core.reset_execution_state_from_seed(&empty).unwrap();
        assert_eq!(
            core.execute(&lower("function f(x) { return x; } f.call(null, 42);"))
                .unwrap()
                .value,
            Value::Int(42)
        );
    }
}
