#![forbid(unsafe_code)]

//! Execute the property-descriptor abstract operations through parsed programs.
//! These cases exercise attributes at their consumers as well as reflection.

use frankenengine_core::ast::ParseGoal;
use frankenengine_core::baseline_interpreter::{
    ExecutionSeed, InterpreterConfig, InterpreterCore, Value,
};
use frankenengine_core::capability::RuntimeCapability;
use frankenengine_core::hash_tiers::ContentHash;
use frankenengine_core::ifc_artifacts::Label;
use frankenengine_core::ir_contract::{
    Ir0Module, Ir1Literal, Ir1Module, Ir1Op, Ir1PropertyKey, Ir3Instruction, Ir3Module,
    IrSchemaVersion, verify_ir3_specialization,
};
use frankenengine_core::lowering_pipeline::{
    LoweringContext, lower_ir0_to_ir3, lower_ir1_to_ir2, lower_ir2_to_ir3,
};
use frankenengine_core::parser::{CanonicalEs2020Parser, Es2020Parser};

fn lower(source: &str) -> Ir3Module {
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Script)
        .expect("descriptor fixture must parse");
    lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "object-descriptors.js"),
        &LoweringContext::new("descriptors", "descriptors", "descriptors"),
    )
    .expect("descriptor fixture must lower")
    .ir3
}

fn configs() -> [InterpreterConfig; 2] {
    [
        InterpreterConfig::quickjs_defaults(),
        InterpreterConfig::v8_defaults(),
    ]
    .map(|mut config| {
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
        ]
        .into_iter()
        .collect();
        config
    })
}

fn assert_output(source: &str, expected: &[&str]) {
    let module = lower(source);
    for config in configs() {
        let result = InterpreterCore::new(config, "object-descriptors")
            .execute(&module)
            .expect("descriptor fixture must execute");
        let actual: Vec<&str> = result
            .console_output
            .iter()
            .map(|entry| entry.message.as_str())
            .collect();
        assert_eq!(actual, expected, "{source}");
    }
}

#[test]
fn legacy_accessor_encoding_cannot_silently_replay_as_ordinary_assignment() {
    let legacy = IrSchemaVersion {
        major: 0,
        minor: 19,
        patch: 0,
    };
    for key in [
        "__franken_ir_accessor_get__:x",
        "__franken_ir_accessor_set__:x",
        "ordinary",
    ] {
        let mut ir1 = Ir1Module::new(ContentHash::compute(b"legacy-accessor"), "legacy-accessor");
        ir1.ops = vec![
            Ir1Op::NewObject { count: 0 },
            Ir1Op::LoadLiteral {
                value: Ir1Literal::Integer(1),
            },
            Ir1Op::SetProperty {
                key: Ir1PropertyKey::Static(key.into()),
            },
            Ir1Op::Return,
        ];
        let mut ir2 = lower_ir1_to_ir2(&ir1).unwrap().module;
        let mut ir3 = lower_ir2_to_ir3(&ir2).unwrap().module;
        ir1.header.schema_version = legacy;
        ir2.header.schema_version = legacy;
        ir3.header.schema_version = legacy;
        if key == "ordinary" {
            assert!(lower_ir1_to_ir2(&ir1).is_ok());
            assert!(lower_ir2_to_ir3(&ir2).is_ok());
            assert!(verify_ir3_specialization(&ir3).is_ok());
        } else {
            assert!(lower_ir1_to_ir2(&ir1).is_err());
            assert!(lower_ir2_to_ir3(&ir2).is_err());
            let error = verify_ir3_specialization(&ir3).unwrap_err();
            assert!(error.message.contains("requires re-lowering"));
        }
    }
    assert_output(
        r#"
        const o = {};
        o['__franken_ir_accessor_get__:x'] = 4;
        o['__franken_ir_accessor_set__:x'] = 5;
        console.log(o['__franken_ir_accessor_get__:x'],
                    o['__franken_ir_accessor_set__:x'], o.x);
        "#,
        &["4 5 undefined"],
    );
}

#[test]
fn exact_descriptor_language_operations_preserve_labels_without_relaxing_external_sinks() {
    for (capability, clearance, declassification_required) in [
        ("builtin:ObjectDefineProperty", Label::Secret, false),
        (
            "builtin:ObjectGetOwnPropertyDescriptor",
            Label::Secret,
            false,
        ),
        ("builtin:ReflectDefineProperty", Label::Secret, false),
        ("builtin:ObjectDefinePropertyExtra", Label::Internal, true),
        (
            "builtin:ObjectGetOwnPropertyDescriptor:extra",
            Label::Internal,
            true,
        ),
        ("builtin:ReflectDefinePropertyExtra", Label::Internal, true),
        ("net.send", Label::Public, true),
        ("fs.write", Label::Internal, true),
    ] {
        let mut module =
            Ir1Module::new(ContentHash::compute(b"descriptor-flow"), "descriptor-flow");
        module.ops = vec![
            Ir1Op::LoadLiteral {
                value: Ir1Literal::String("secret_value".into()),
            },
            Ir1Op::HostCall {
                capability: capability.into(),
                arg_count: 1,
            },
            Ir1Op::Return,
        ];
        let ir2 = lower_ir1_to_ir2(&module).unwrap().module;
        let flow = ir2.ops[1].flow.as_ref().unwrap();
        assert_eq!(flow.data_label, Label::Secret);
        assert_eq!(flow.sink_clearance, clearance, "{capability}");
        assert_eq!(
            flow.declassification_required, declassification_required,
            "{capability}"
        );
        let ir3 = lower_ir2_to_ir3(&ir2).unwrap().module;
        assert_eq!(
            ir3.instructions
                .iter()
                .any(|instruction| matches!(instruction,
                    Ir3Instruction::HostCall { capability, .. } if capability.0 == "ifc.check_flow"
                )),
            declassification_required,
            "{capability}"
        );
    }
}

#[test]
fn array_builtins_enforce_descriptor_restrictions_and_iteration_ignores_enumerability() {
    assert_output(
        r#"
        const protectedEnd = [1, 2];
        Object.defineProperty(protectedEnd, '1', {configurable: false});
        let popFailed = false;
        try { protectedEnd.pop(); } catch (error) { popFailed = error.name === 'TypeError'; }
        console.log(popFailed, protectedEnd.length, protectedEnd[1], 1 in protectedEnd);
        const fixed = [3];
        Object.defineProperty(fixed, 'length', {writable: false});
        let pushFailed = false;
        try { fixed.push(4); } catch (error) { pushFailed = error.name === 'TypeError'; }
        console.log(pushFailed, fixed.length, 1 in fixed, fixed[0]);
        const hidden = [10, 20];
        Object.defineProperty(hidden, '0', {enumerable: false});
        console.log(Object.keys(hidden).join(','), [...hidden].join(','));
    "#,
        &["true 2 2 true", "true 1 false 3", "1 10,20"],
    );
}

#[test]
fn missing_fields_default_only_when_creating_a_property() {
    assert_output(
        r#"
        const object = { existing: 1 };
        console.log(Object.defineProperty(object, 'hidden', {value: 7}) === object);
        let descriptor = Object.getOwnPropertyDescriptor(object, 'hidden');
        console.log(descriptor.value, descriptor.writable, descriptor.enumerable, descriptor.configurable);
        console.log(Object.getOwnPropertyDescriptor(object, 'missing') === undefined);
        Object.defineProperty(object, 'existing', {value: 2});
        descriptor = Object.getOwnPropertyDescriptor(object, 'existing');
        console.log(descriptor.value, descriptor.writable, descriptor.enumerable, descriptor.configurable);
        Object.defineProperty(object, 'existing', {enumerable: false});
        Object.defineProperty(object, 'existing', {});
        descriptor = Object.getOwnPropertyDescriptor(object, 'existing');
        console.log(descriptor.value, descriptor.writable, descriptor.enumerable, descriptor.configurable);
        Object.defineProperty(object, 'empty', {});
        descriptor = Object.getOwnPropertyDescriptor(object, 'empty');
        console.log(descriptor.value === undefined, descriptor.writable, descriptor.enumerable, descriptor.configurable);
        "#,
        &[
            "true",
            "7 false false false",
            "true",
            "2 true true true",
            "2 true false true",
            "true false false false",
        ],
    );
}

#[test]
fn descriptor_kind_transitions_preserve_unspecified_fields_and_accessor_identity() {
    assert_output(
        r#"
        const object = {};
        let reads = 0;
        let stored = 0;
        function getter() { reads++; return 7; }
        function setter(value) { stored = value; }
        Object.defineProperty(object, 'x', {get: getter, set: setter, enumerable: true, configurable: true});
        let descriptor = Object.getOwnPropertyDescriptor(object, 'x');
        console.log(descriptor.get === getter, descriptor.set === setter, 'value' in descriptor, 'writable' in descriptor, reads);
        object.x = 12;
        console.log(object.x, stored, reads);
        Object.defineProperty(object, 'x', {value: 11});
        descriptor = Object.getOwnPropertyDescriptor(object, 'x');
        console.log(object.x, descriptor.writable, descriptor.enumerable, descriptor.configurable, 'get' in descriptor);
        Object.defineProperty(object, 'x', {set: setter});
        descriptor = Object.getOwnPropertyDescriptor(object, 'x');
        console.log(object.x === undefined, descriptor.get === undefined, descriptor.set === setter, descriptor.enumerable, descriptor.configurable);
        object.x = 19;
        console.log(stored, reads);
        "#,
        &[
            "true true false false 0",
            "7 12 1",
            "11 false true true false",
            "true true true true true",
            "19 1",
        ],
    );
}

#[test]
fn nonconfigurable_definitions_use_same_value_and_leave_rejected_targets_unchanged() {
    assert_output(
        r#"
        const object = {};
        Object.defineProperty(object, 'nan', {value: NaN});
        Object.defineProperty(object, 'zero', {value: -0});
        console.log(Reflect.defineProperty(object, 'nan', {value: NaN}));
        console.log(Reflect.defineProperty(object, 'zero', {value: -0}), Reflect.defineProperty(object, 'zero', {value: 0}));
        console.log(Reflect.defineProperty(object, 'nan', {}), Reflect.defineProperty(object, 'nan', {writable: true}));
        console.log(Reflect.defineProperty(object, 'nan', {enumerable: true}), Reflect.defineProperty(object, 'nan', {configurable: true}));
        console.log(Reflect.defineProperty(object, 'nan', {get: undefined}));
        let failed = false;
        try { Object.defineProperty(object, 'zero', {value: 1}); } catch (error) { failed = error.name === 'TypeError'; }
        console.log(failed, 1 / object.zero);
        function first() { return 1; }
        function second() { return 2; }
        Object.defineProperty(object, 'accessor', {get: first});
        console.log(Reflect.defineProperty(object, 'accessor', {get: first}), Reflect.defineProperty(object, 'accessor', {get: second}), object.accessor);
        "#,
        &[
            "true",
            "true false",
            "true false",
            "false false",
            "false",
            "true -Infinity",
            "true false 1",
        ],
    );
}

#[test]
fn descriptor_conversion_observes_inherited_getters_in_specification_order() {
    assert_output(
        r#"
        let trace = '';
        class Descriptor {
            get enumerable() { trace += 'e'; return true; }
            get configurable() { trace += 'c'; return true; }
            get value() { trace += 'v'; return 42; }
            get writable() { trace += 'w'; return true; }
        }
        const object = {};
        Object.defineProperty(object, 'x', new Descriptor());
        console.log(trace, object.x);
        function descriptor() {}
        Object.defineProperty(descriptor, 'value', {get: function() { trace += 'f'; return 9; }});
        Object.defineProperty(object, 'y', descriptor);
        console.log(trace, object.y);
        const invalid = {
            get enumerable() { trace += 'E'; return true; },
            get configurable() { trace += 'C'; return true; },
            get value() { trace += 'V'; return 1; },
            get writable() { trace += 'W'; return true; },
            get get() { trace += 'G'; return undefined; },
            get set() { trace += 'S'; return undefined; }
        };
        let failed = false;
        try { Object.defineProperty(object, 'bad', invalid); } catch (error) { failed = error.name === 'TypeError'; }
        console.log(trace, failed, 'bad' in object);
        "#,
        &["ecvw 42", "ecvwf 9", "ecvwfECVWGS true false"],
    );
}

#[test]
fn key_conversion_precedes_descriptor_conversion_and_preserves_exact_abrupt_values() {
    assert_output(
        r#"
        let trace = '';
        const object = {};
        const key = { [Symbol.toPrimitive](hint) { trace += hint; return 'x'; } };
        const descriptor = {get value() { trace += 'v'; return 5; }};
        Object.defineProperty(object, key, descriptor);
        console.log(trace, object.x);
        const fallback = { toString() { trace += 't'; return {}; }, valueOf() { trace += 'n'; return 'y'; } };
        Object.defineProperty(object, fallback, {value: 6});
        console.log(trace, object.y);
        const failure = {};
        const badKey = { [Symbol.toPrimitive]() { throw failure; } };
        let same = false;
        try { Object.defineProperty(object, badKey, descriptor); } catch (error) { same = error === failure; }
        console.log(same, trace);
        const badDescriptor = {get value() { throw failure; }};
        same = false;
        try { Reflect.defineProperty(object, 'bad', badDescriptor); } catch (error) { same = error === failure; }
        console.log(same, 'bad' in object);
        let invalid = 0;
        try { Reflect.defineProperty(object, 'bad', {get: 7}); } catch (error) { if (error.name === 'TypeError') invalid++; }
        try { Object.defineProperty(object, 'bad', {set: null}); } catch (error) { if (error.name === 'TypeError') invalid++; }
        try { Object.defineProperty(1, key, descriptor); } catch (error) { if (error.name === 'TypeError') invalid++; }
        console.log(invalid, trace);
        "#,
        &[
            "stringv 5",
            "stringvtn 6",
            "true stringvtn",
            "true false",
            "3 stringvtn",
        ],
    );
}

#[test]
fn symbol_and_exact_utf16_keys_have_independent_descriptors() {
    assert_output(
        r#"
        const object = {};
        const first = Symbol('same');
        const second = Symbol('same');
        Object.defineProperty(object, first, {value: 11, enumerable: true});
        Object.defineProperty(object, second, {value: 22});
        Object.defineProperty(object, '\ud800', {value: 33, configurable: true});
        Object.defineProperty(object, '\ufffd', {value: 44});
        console.log(object[first], object[second], object['\ud800'], object['\ufffd']);
        console.log(Object.getOwnPropertyDescriptor(object, first).enumerable, Object.getOwnPropertyDescriptor(object, second).enumerable);
        console.log(Object.getOwnPropertyDescriptor(object, '\ud800').configurable, Object.getOwnPropertyDescriptor(object, '\ufffd').configurable);
        console.log(Object.getOwnPropertySymbols(object).length, Object.getOwnPropertyNames(object).length, Reflect.ownKeys(object).length);
        const copy = {...object};
        console.log(copy[first], copy[second] === undefined);
        "#,
        &[
            "11 22 33 44",
            "true false",
            "true false",
            "2 2 4",
            "11 true",
        ],
    );
}

#[test]
fn enumeration_consumers_exclude_non_enumerable_properties_without_invoking_them() {
    assert_output(
        r#"
        const object = {visible: 3};
        let calls = 0;
        Object.defineProperty(object, 'hidden', {get: function() { calls++; return 7; }});
        Object.defineProperty(object, 'shown', {get: function() { calls++; return 8; }, enumerable: true});
        console.log(Object.keys(object).join(','), calls);
        console.log(Object.values(object).join(','), calls);
        console.log(Object.entries(object)[1][0], calls);
        let keys = '';
        for (const key in object) keys += key + ',';
        console.log(keys, calls);
        const copy = {...object};
        const assigned = Object.assign({}, object);
        const {visible, ...rest} = object;
        console.log(copy.shown, assigned.shown, rest.shown, 'hidden' in copy, 'hidden' in assigned, 'hidden' in rest, calls);
        console.log(JSON.stringify(object), calls);
        console.log(Object.getOwnPropertyNames(object).join(','));
        "#,
        &[
            "visible,shown 0",
            "3,8 1",
            "shown 2",
            "visible,shown, 2",
            "8 8 8 false false false 5",
            "{\"visible\":3,\"shown\":8} 6",
            "visible,hidden,shown",
        ],
    );
}

#[test]
fn definition_uses_own_properties_and_assignment_uses_inherited_setters() {
    assert_output(
        r#"
        let calls = 0;
        class Parent { set x(value) { calls += value; } }
        const child = new Parent();
        child.x = 2;
        Object.defineProperty(child, 'x', {value: 7, writable: true, enumerable: true, configurable: true});
        child.x = 9;
        console.log(calls, child.x, Object.getOwnPropertyDescriptor(child, 'x').value);
        const target = {};
        Object.defineProperty(target, 'fixed', {value: 1});
        let failed = false;
        try { Object.assign(target, {early: 2, fixed: 3, late: 4}); } catch (error) { failed = error.name === 'TypeError'; }
        console.log(failed, target.early, target.fixed, 'late' in target);
        "#,
        &["2 9 9", "true 2 1 false"],
    );
}

#[test]
fn descriptor_methods_are_first_class_and_respect_lexical_shadowing() {
    assert_output(
        r#"
        const define = Object.defineProperty;
        const inspect = Object.getOwnPropertyDescriptor;
        const reflect = Reflect.defineProperty;
        function callable() { return 1; }
        console.log(define(callable, 'extra', {value: 7}) === callable, inspect(callable, 'extra').value);
        console.log(reflect(callable, 'extra', {value: 8}), callable.extra, callable());
        function local(Object, Reflect) { return Object.defineProperty() + Reflect.defineProperty(); }
        console.log(local({defineProperty() { return 10; }}, {defineProperty() { return 20; }}));
        "#,
        &["true 7", "false 7 1", "30"],
    );
}

#[test]
fn primitive_reflection_uses_string_exotic_descriptors_and_rejects_nullish_targets_first() {
    assert_output(
        r#"
        const character = Object.getOwnPropertyDescriptor('A💩', '1');
        const length = Object.getOwnPropertyDescriptor('A💩', 'length');
        console.log(character.value.length, character.value.charCodeAt(0), character.writable, character.enumerable, character.configurable);
        console.log(length.value, length.writable, length.enumerable, length.configurable);
        console.log(Object.getOwnPropertyDescriptor(7, 'x') === undefined, Object.getOwnPropertyDescriptor(true, 'x') === undefined, Object.getOwnPropertyDescriptor(Symbol('s'), 'description') === undefined);
        let calls = 0;
        const key = {toString() { calls++; return 'x'; }};
        let rejected = 0;
        try { Object.getOwnPropertyDescriptor(null, key); } catch (error) { if (error.name === 'TypeError') rejected++; }
        try { Object.getOwnPropertyDescriptor(undefined, key); } catch (error) { if (error.name === 'TypeError') rejected++; }
        console.log(rejected, calls);
        "#,
        &[
            "1 55357 false true false",
            "3 false false false",
            "true true true",
            "2 0",
        ],
    );
}

#[test]
fn a_non_enumerable_own_name_shadows_the_same_inherited_name_during_for_in() {
    assert_output(
        r#"
        class Parent {}
        Object.defineProperty(Parent.prototype, 'shadowed', {value: 1, enumerable: true});
        Object.defineProperty(Parent.prototype, 'inherited', {value: 2, enumerable: true});
        const child = new Parent();
        child.own = 3;
        Object.defineProperty(child, 'shadowed', {value: 4});
        let names = '';
        for (const name in child) names += name + ',';
        console.log(names);
        "#,
        &["own,inherited,"],
    );
}

#[test]
fn array_length_definitions_observe_index_constraints_and_partial_shrink_rollback() {
    assert_output(
        r#"
        const array = [10, 20, 30, 40];
        const original = Object.getOwnPropertyDescriptor(array, 'length');
        console.log(original.value, original.writable, original.enumerable, original.configurable);
        Object.defineProperty(array, '2', {configurable: false});
        console.log(Reflect.defineProperty(array, 'length', {value: 1, writable: false}));
        console.log(array.length, 3 in array, 2 in array, Object.getOwnPropertyDescriptor(array, 'length').writable);
        console.log(Reflect.defineProperty(array, '3', {value: 9}), Reflect.defineProperty(array, '1', {value: 8}), array[1]);
        console.log(Reflect.defineProperty(array, 'length', {writable: true}), Reflect.defineProperty(array, 'length', {enumerable: true}));
        const growing = [];
        Object.defineProperty(growing, '4', {value: 42});
        console.log(growing.length, growing[4], Object.keys(growing).length);
        let rangeError = false;
        try { Object.defineProperty(growing, 'length', {value: 1.5}); } catch (error) { rangeError = error.name === 'RangeError'; }
        console.log(rangeError, growing.length);
        let coercions = 0;
        Object.defineProperty(growing, 'length', {value: {valueOf() { coercions++; return 5; }}});
        console.log(coercions, growing.length);
        "#,
        &[
            "4 true false false",
            "false",
            "3 false true false",
            "false true 8",
            "false false",
            "5 42 0",
            "true 5",
            "2 5",
        ],
    );
}

#[test]
fn descriptor_values_and_attribute_bits_preserve_confidentiality() {
    for (source, input, expected) in [
        (
            "const input = 987654; const object = {}; Object.defineProperty(object, 'x', {value: input}); object.x;",
            Value::Int(42),
            Value::Int(42),
        ),
        (
            "const input = 987654; const object = {}; Object.defineProperty(object, 'x', {value: 7, enumerable: input}); Object.getOwnPropertyDescriptor(object, 'x').enumerable;",
            Value::Bool(true),
            Value::Bool(true),
        ),
        (
            "const input = 987654; const object = {}; Object.defineProperty(object, 'x', {value: 7, enumerable: input}); Object.keys(object).length;",
            Value::Bool(false),
            Value::Int(0),
        ),
        (
            "const input = 987654; const object = {}; Object.defineProperty(object, 'x', {value: 7, writable: input}); Reflect.defineProperty(object, 'x', {value: 8});",
            Value::Bool(false),
            Value::Bool(false),
        ),
        (
            "const input = 987654; const object = {}; Object.defineProperty(object, 'x', {value: 7, configurable: input}); Reflect.defineProperty(object, 'x', {enumerable: true});",
            Value::Bool(false),
            Value::Bool(false),
        ),
    ] {
        let mut module = lower(source);
        let mut replacements = 0;
        for instruction in &mut module.instructions {
            if let Ir3Instruction::LoadInt { dst, value: 987654 } = *instruction {
                *instruction = Ir3Instruction::Move { dst, src: 255 };
                replacements += 1;
            }
        }
        assert_eq!(replacements, 1);
        for config in configs() {
            for label in [
                Label::Secret,
                Label::Custom {
                    name: "descriptor-attributes".repeat(16),
                    level: 4,
                },
            ] {
                let mut core = InterpreterCore::new(config.clone(), "descriptor-labels");
                core.write_register(255, input.clone());
                let mut wire = serde_json::to_value(core.capture_execution_seed()).unwrap();
                wire["register_labels"][255] = serde_json::to_value(&label).unwrap();
                core.reset_execution_state_from_seed(
                    &serde_json::from_value::<ExecutionSeed>(wire).unwrap(),
                )
                .unwrap();
                let result = core.execute(&module).unwrap();
                assert_eq!(result.value, expected, "{source}");
                assert_eq!(result.completion_label, label, "{source}");
            }
        }
    }
}

#[test]
fn replay_seed_roundtrip_preserves_exact_key_attributes_and_array_invariants() {
    let create = lower(
        r#"
        const object = {array: [1, 2]};
        Object.defineProperty(object, '\ud800', {value: 7});
        Object.defineProperty(object, '\ufffd', {value: 8, configurable: true});
        Object.defineProperty(object, Symbol.for('persisted'), {value: 9, enumerable: true});
        Object.defineProperty(object.array, 'length', {writable: false});
        object;
        "#,
    );
    let mut inspect = lower(
        r#"
        const object = 987654;
        console.log(object['\ud800'], object['\ufffd'], object[Symbol.for('persisted')]);
        console.log(Object.getOwnPropertyDescriptor(object, '\ud800').configurable, Object.getOwnPropertyDescriptor(object, '\ufffd').configurable);
        console.log(Object.getOwnPropertyDescriptor(object, Symbol.for('persisted')).enumerable);
        console.log(Reflect.defineProperty(object, '\ud800', {value: 11}), Reflect.defineProperty(object, '\ufffd', {value: 12}));
        console.log(Reflect.defineProperty(object.array, '2', {value: 3}), object.array.length);
        "#,
    );
    let mut replacements = 0;
    for instruction in &mut inspect.instructions {
        if let Ir3Instruction::LoadInt { dst, value: 987654 } = *instruction {
            *instruction = Ir3Instruction::Move { dst, src: 255 };
            replacements += 1;
        }
    }
    assert_eq!(replacements, 1);
    for config in configs() {
        let mut original = InterpreterCore::new(config.clone(), "descriptor-seed-create");
        let object = original.execute(&create).unwrap().value;
        original.write_register(255, object);
        let seed = original.capture_execution_seed();
        let restored: ExecutionSeed =
            serde_json::from_slice(&serde_json::to_vec(&seed).unwrap()).unwrap();
        assert_eq!(seed, restored);
        let mut replay = InterpreterCore::new(config, "descriptor-seed-inspect");
        replay.reset_execution_state_from_seed(&restored).unwrap();
        let result = replay.execute(&inspect).unwrap();
        let output: Vec<&str> = result
            .console_output
            .iter()
            .map(|entry| entry.message.as_str())
            .collect();
        assert_eq!(
            output,
            ["7 8 9", "false true", "true", "false true", "false 2"]
        );
    }
}
