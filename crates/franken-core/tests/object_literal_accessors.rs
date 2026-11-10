//! Real source-to-runtime accessor coverage for both native core profiles.

use std::collections::BTreeSet;

use frankenengine_core::ast::{ObjectPropertyKind, ParseGoal, Statement};
use frankenengine_core::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_core::capability::RuntimeCapability;
use frankenengine_core::ir_contract::{
    AccessorKind, Ir0Module, Ir3Instruction, IrSchemaVersion, verify_ir3_specialization,
};
use frankenengine_core::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_core::parser::{CanonicalEs2020Parser, Es2020Parser};

fn lower(source: &str) -> frankenengine_core::ir_contract::Ir3Module {
    let tree = CanonicalEs2020Parser.parse(source, ParseGoal::Module)
        .expect("parse object accessor source");
    lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "object-literal-accessors.mjs"),
        &LoweringContext::new("object-accessors", "object-accessors", "object-accessors"),
    ).expect("lower object accessor source").ir3
}

fn assert_output(source: &str, expected: &[&str]) {
    let module = lower(source);
    for throughput in [false, true] {
        let mut config = if throughput {
            InterpreterConfig::v8_defaults()
        } else {
            InterpreterConfig::quickjs_defaults()
        };
        config.granted_capabilities = BTreeSet::from([
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
        ]);
        let result = InterpreterCore::new(config, "object-accessors")
            .execute(&module).expect("execute object accessor source");
        let output: Vec<_> = result.console_output.into_iter().map(|line| line.message).collect();
        assert_eq!(output, expected, "throughput={throughput}: {source}");
    }
}

#[test]
fn getter_setter_pair_uses_receiver_and_assignment_value() {
    assert_output(r#"
        const object = {
            stored: 1,
            get value() { return this.stored * 2; },
            set value(next) { this.stored = next + 1; },
            get() { return 'method:get'; },
            set() { return 'method:set'; }
        };
        console.log(object.value);
        console.log(object.value = 20);
        console.log(object.value);
        console.log(object.get());
        console.log(object.set());
    "#, &["2", "20", "42", "method:get", "method:set"]);
}

#[test]
fn inherited_accessor_uses_child_receiver() {
    assert_output(r#"
        const parent = {
            stored: 2,
            get value() { return this.stored; },
            set value(next) { this.stored = next; }
        };
        const child = { stored: 7 };
        child.__proto__ = parent;
        console.log(child.value);
        child.value = 11;
        console.log(child.value);
        console.log(parent.value);
    "#, &["7", "11", "2"]);
}

#[test]
fn computed_keys_evaluate_once_before_getter_bodies() {
    assert_output(r#"
        function key(name) { console.log('key:' + name); return name; }
        const object = {
            get [key('value')]() { console.log('get'); return this.saved; },
            saved: 4,
            set [key('value')](next) { console.log('set'); this.saved = next; },
            tail: key('tail')
        };
        console.log('created');
        object.value = 9;
        console.log(object.value);
    "#, &["key:value", "key:value", "key:tail", "created", "set", "get", "9"]);
}

#[test]
fn symbol_accessors_keep_identity_and_pairing_separate_from_strings() {
    assert_output(r#"
        const first = Symbol('slot');
        const second = Symbol('slot');
        const object = {
            stored: 3,
            get [first]() { return this.stored; },
            set [first](next) { this.stored = next; },
            get [second]() { return 91; },
            get 'Symbol(slot)'() { return 27; }
        };
        object[first] = 42;
        console.log(object[first]);
        console.log(object[second]);
        console.log(object['Symbol(slot)']);
        const keys = Object.getOwnPropertySymbols(object);
        console.log(keys.length);
        console.log(keys[0] === first);
        console.log(keys[1] === second);
    "#, &["42", "91", "27", "2", "true", "true"]);
}

#[test]
fn static_and_computed_names_preserve_exact_utf16_and_numeric_identity() {
    assert_output(r#"
        const object = {
            get '\uD800'() { return 11; },
            get ['\uD801']() { return 12; },
            get 0x10() { return 16; },
            get /* comment */ async() { return 17; },
            set['saved'](value) { this.result = value; }
        };
        object.saved = 19;
        console.log(object['\uD800']);
        console.log(object['\uD801']);
        console.log(object[16]);
        console.log(object.async);
        console.log(object.result);
    "#, &["11", "12", "16", "17", "19"]);
}

#[test]
fn redefining_accessor_halves_preserves_order_and_data_replacement_clears_them() {
    assert_output(r#"
        const object = {
            first: 1,
            get value() { return 10; },
            middle: 2,
            set value(next) { this.saved = next; },
            get value() { return 20; },
            last: 3
        };
        object.value = 7;
        console.log(object.value);
        console.log(object.saved);
        console.log(Object.keys(object).join(','));
        const replaced = {
            get value() { return 1; },
            value: 2,
            set value(next) { this.saved = next; }
        };
        console.log(replaced.value);
        replaced.value = 9;
        console.log(replaced.saved);
        const data = { set value(next) { throw 'obsolete'; }, value: 5 };
        data.value = 6;
        console.log(data.value);
    "#, &["20", "7", "first,value,middle,last,saved", "undefined", "9", "6"]);
}

#[test]
fn accessor_named_proto_is_a_property_and_its_setter_runs() {
    assert_output(r#"
        const object = {
            get __proto__() { return this.saved; },
            set __proto__(value) { this.saved = value; }
        };
        object.__proto__ = 42;
        console.log(object.__proto__);
        console.log(Object.keys(object).join(','));
    "#, &["42", "__proto__,saved"]);
}

#[test]
fn super_accessors_use_home_object_and_actual_receiver() {
    assert_output(r#"
        const base = {
            get value() { return this.stored + 1; },
            set value(next) { this.stored = next - 1; }
        };
        const home = {
            get value() { return super.value + 1; },
            set value(next) { super.value = next - 1; }
        };
        home.__proto__ = base;
        const child = { stored: 40 };
        child.__proto__ = home;
        console.log(child.value);
        child.value = 22;
        console.log(child.stored);
        console.log(child.value);
        console.log(base.stored);
        home.__proto__ = { value: 99 };
        console.log(child.value);
    "#, &["42", "20", "22", "undefined", "100"]);
}

#[test]
fn super_updates_and_arrow_receiver_preserve_reference_semantics() {
    assert_output(r#"
        const base = {
            get value() { return this.stored; },
            set value(next) { this.stored = next; }
        };
        const home = {
            get value() {
                const read = () => super.value;
                return read();
            },
            bump() { const old = super.value++; super.value += 2; return old; }
        };
        home.__proto__ = base;
        const child = { stored: 7 };
        child.__proto__ = home;
        console.log(child.value);
        console.log(child.bump());
        console.log(child.value);
    "#, &["7", "7", "10"]);
}

#[test]
fn abrupt_getter_and_setter_completions_unwind_through_finally() {
    assert_output(r#"
        const token = { id: 42 };
        const object = {
            get value() { try { throw token; } finally { console.log('get:finally'); } },
            set value(next) { throw next; }
        };
        try { console.log(object.value); } catch (error) { console.log(error === token); }
        try { object.value = token; } catch (error) { console.log(error === token); }
        console.log('after');
    "#, &["get:finally", "true", "true", "after"]);
}

#[test]
fn accessor_thenables_are_adopted_by_promises_and_await() {
    assert_output(r#"
        const object = {
            value: 42,
            get then() {
                console.log('getter');
                return function(resolve) { resolve(this.value); };
            }
        };
        async function read() { return await object; }
        read().then(value => console.log(value));
        console.log('sync');
    "#, &["getter", "sync", "42"]);
}

#[test]
fn parser_rejects_invalid_accessor_parameter_lists() {
    for source in [
        "const object = { get value(x) {} };",
        "const object = { get value(...x) {} };",
        "const object = { set value() {} };",
        "const object = { set value(x, y) {} };",
        "const object = { set value(...x) {} };",
        "const object = { get value() {} trailing };",
    ] {
        assert!(CanonicalEs2020Parser.parse(source, ParseGoal::Module).is_err(), "{source}");
    }
}

#[test]
fn accessor_kinds_survive_ast_ir_and_schema_verification() {
    let source = "const object = { get value() { return 1; }, set value(next) {} };";
    let tree = CanonicalEs2020Parser.parse(source, ParseGoal::Module).unwrap();
    let Statement::VariableDeclaration(declaration) = &tree.body[0] else { panic!("declaration") };
    let frankenengine_core::ast::Expression::ObjectLiteral(properties) =
        declaration.declarations[0].init.as_ref().unwrap() else { panic!("object") };
    assert_eq!(properties[0].kind, ObjectPropertyKind::Get);
    assert_eq!(properties[1].kind, ObjectPropertyKind::Set);
    let mut module = lower(source);
    let kinds: Vec<_> = module.instructions.iter().filter_map(|instruction| match instruction {
        Ir3Instruction::DefineAccessor { kind, .. } => Some(*kind),
        _ => None,
    }).collect();
    assert_eq!(kinds, [AccessorKind::Get, AccessorKind::Set]);
    let wire = serde_json::to_vec(&module).unwrap();
    let restored = serde_json::from_slice::<frankenengine_core::ir_contract::Ir3Module>(&wire).unwrap();
    assert_eq!(restored.content_hash(), module.content_hash());
    module.header.schema_version = IrSchemaVersion { major: 0, minor: 15, patch: 0 };
    assert!(verify_ir3_specialization(&module).is_err());
}

#[test]
fn computed_accessor_returned_method_keeps_receiver_and_single_key_evaluation() {
    assert_output(r#"
        const key = Symbol('method');
        let reads = 0;
        function propertyKey() { reads += 1; return key; }
        const object = {
            value: 42,
            get [key]() {
                console.log('get');
                return function() { return this.value; };
            }
        };
        console.log(object[propertyKey()]());
        console.log(reads);
    "#, &["get", "42", "1"]);
}
