#![forbid(unsafe_code)]

//! Source mode, property refusal, and generated own-definition behavior.

use frankenengine_core::ast::{
    Expression, ExpressionStatement, ParseGoal, SourceSpan, Statement, SyntaxTree,
};
use frankenengine_core::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_core::capability::RuntimeCapability;
use frankenengine_core::ir_contract::{
    Ir0Module, Ir3Instruction, Ir3Module, IrSchemaVersion, verify_ir3_specialization,
};
use frankenengine_core::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_core::parser::{CanonicalEs2020Parser, Es2020Parser};

fn lower(source: &str, goal: ParseGoal) -> Ir3Module {
    let tree = CanonicalEs2020Parser.parse(source, goal).expect(source);
    lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "property-write-modes.js"),
        &LoweringContext::new(
            "property-write-modes",
            "property-write-modes",
            "property-write-modes",
        ),
    )
    .expect(source)
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

fn assert_output(source: &str, goal: ParseGoal, expected: &[&str]) {
    let module = lower(source, goal);
    for config in configs() {
        let result = InterpreterCore::new(config, "property-write-modes")
            .execute(&module)
            .expect(source);
        let output: Vec<_> = result
            .console_output
            .iter()
            .map(|entry| entry.message.as_str())
            .collect();
        assert_eq!(output, expected, "{source}");
    }
}

#[test]
fn directives_preserve_raw_spelling_prologue_membership_and_trivia() {
    for (prefix, expected) in [
        ("'use strict';", "TypeError 1"),
        ("'use strict'\n", "TypeError 1"),
        ("/* leading */'use strict' /* trailing */;", "TypeError 1"),
        (
            "'prefix'; /* bridge */ 'use strict' // comment\n",
            "TypeError 1",
        ),
        ("'prefix'\n'use strict'\n", "TypeError 1"),
        ("", "sloppy 1"),
        (r#"'use\x20strict';"#, "sloppy 1"),
        (r#"'use\u0020strict';"#, "sloppy 1"),
        ("('use strict');", "sloppy 1"),
        (";'use strict';", "sloppy 1"),
        ("'prefix';;'use strict';", "sloppy 1"),
        ("0;'use strict';", "sloppy 1"),
        ("('prefix');'use strict';", "sloppy 1"),
    ] {
        let source = format!(
            "{prefix} const o = {{ get x() {{ return 1; }} }}; let result = 'sloppy'; try {{ o.x = 2; }} catch (e) {{ result = e.name; }} console.log(result, o.x);"
        );
        assert_output(&source, ParseGoal::Script, &[expected]);
    }
}

#[test]
fn module_and_inherited_function_modes_do_not_leak_to_siblings() {
    assert_output(
        "const o = { get x() { return 1; } }; try { o.x = 2; } catch (e) { console.log(e.name); }",
        ParseGoal::Module,
        &["TypeError"],
    );
    assert_output(
        r#"
        const o = { get x() { return 1; } };
        function outer() { 'use strict'; return function() { return () => { o.x = 2; }; }; }
        function sloppy() { o.x = 3; return 'sloppy'; }
        try { outer()()(); } catch (e) { console.log(e.name); }
        console.log(sloppy(), o.x);
        function defaults() { 'use strict'; return function(a = (o.x = 4)) { return a; }; }
        try { defaults()(); } catch (e) { console.log(e.name); }
    "#,
        ParseGoal::Script,
        &["TypeError", "sloppy 1", "TypeError"],
    );
}

#[test]
fn descriptors_refuse_sloppy_writes_and_strict_writes_throw_after_rhs() {
    assert_output(
        r#"
        const o = {};
        Object.defineProperty(o, 'x', { value: 1, writable: false, configurable: false });
        let trace = '';
        function rhs() { trace += 'r'; return 2; }
        console.log(o.x = rhs(), o.x, delete o.x, trace);
        function strict() { 'use strict'; try { o.x = rhs(); } catch (e) { console.log(e.name, trace); }
            try { delete o.x; } catch (e) { console.log(e.name, o.x); } }
        strict();
    "#,
        ParseGoal::Script,
        &["2 1 false r", "TypeError rr", "TypeError 1"],
    );
}

#[test]
fn compound_and_update_assignments_evaluate_references_once() {
    assert_output(
        r#"
        'use strict';
        let trace = '';
        const o = { get x() { trace += 'g'; return 4; } };
        function object() { trace += 'o'; return o; }
        function key() { trace += 'k'; return 'x'; }
        function rhs() { trace += 'r'; return 3; }
        try { object()[key()] += rhs(); } catch (e) { console.log(e.name, trace); }
        trace = '';
        try { object()[key()]++; } catch (e) { console.log(e.name, trace); }
    "#,
        ParseGoal::Script,
        &["TypeError okgr", "TypeError okg"],
    );
}

#[test]
fn setter_throws_remain_exact_in_both_modes() {
    for prefix in ["", "'use strict';"] {
        let source = format!(
            "{prefix} const sentinel = {{}}; let trace = ''; const o = {{ set x(value) {{ trace += value; throw sentinel; }} }}; try {{ o.x = 7; }} catch (e) {{ console.log(e === sentinel, trace); }}"
        );
        assert_output(&source, ParseGoal::Script, &["true 7"]);
    }
}

#[test]
fn class_heritage_keys_methods_and_defaults_are_strict() {
    assert_output(
        r#"
        const o = { get x() { return 1; } };
        class Base {}
        try { class Heritage extends (o.x = 2, Base) {} } catch (e) { console.log('heritage', e.name); }
        try { const Key = class { [(o.x = 2, 'm')]() {} }; } catch (e) { console.log('key', e.name); }
        class Methods { run() { o.x = 2; } constructor(a = (o.x = 2)) {} }
        try { new Methods(); } catch (e) { console.log('default', e.name); }
        try { new Methods(1).run(); } catch (e) { console.log('method', e.name); }
        o.x = 2;
        console.log('sloppy', o.x);
    "#,
        ParseGoal::Script,
        &[
            "heritage TypeError",
            "key TypeError",
            "default TypeError",
            "method TypeError",
            "sloppy 1",
        ],
    );
}

#[test]
fn computed_class_methods_and_accessors_keep_names_keys_and_order() {
    assert_output(
        r#"
        let trace = '';
        function key(value) { trace += value; return value; }
        class C {
            [key('m')]() { return 7; }
            get [key('x')]() { return this.value; }
            set [key('x')](value) { this.value = value; }
            '__franken_ir_accessor_get__:literal'() { return 9; }
        }
        const c = new C(); c.x = 4;
        const descriptor = Object.getOwnPropertyDescriptor(C.prototype, 'x');
        console.log(trace, c.m(), c.x, c['__franken_ir_accessor_get__:literal']());
        console.log(c.m.name, descriptor.get.name, descriptor.set.name, descriptor.enumerable);
    "#,
        ParseGoal::Script,
        &["mxx 7 4 9", "m get x set x false"],
    );
}

#[test]
fn static_inheritance_and_accessor_super_keep_receiver_identity() {
    assert_output(
        r#"
        class Base {
            static inherited() { return this.value; }
            static get x() { return this.value; }
            static set x(value) { this.value = value; }
        }
        class Child extends Base {
            static get x() { return super.x + 1; }
            static set x(value) { super.x = value + 2; }
        }
        Child.x = 5;
        console.log(Child.value, Child.x, Child.inherited(), Base.value);
    "#,
        ParseGoal::Script,
        &["7 8 7 undefined"],
    );
}

#[test]
fn lazy_constructor_prototypes_shadow_inherited_descriptors() {
    assert_output(
        r#"
        class Base { base() { return 1; } }
        const basePrototype = Object.getOwnPropertyDescriptor(Base, 'prototype').value;
        class Child extends Base { child() { return 2; } }
        const child = new Child();
        console.log(Child.prototype !== basePrototype,
            Object.getOwnPropertyDescriptor(basePrototype, 'child') === undefined,
            child.base(), child.child());
        function Ordinary() {}
        const replacement = { value: 9 };
        Object.defineProperty(Ordinary, 'prototype', { value: replacement, writable: false });
        console.log(Ordinary.prototype === replacement, new Ordinary().value);
    "#,
        ParseGoal::Script,
        &["true true 1 2", "true 9"],
    );
}

#[test]
fn inherited_super_setters_accept_null_and_primitive_receivers() {
    assert_output(
        r#"
        let captured;
        class Base { set x(value) { captured = this; } }
        class Child extends Base { run() { super.x = 1; } }
        Child.prototype.run.call(null);
        console.log(captured === null);
        Child.prototype.run.call(7);
        console.log(captured === 7);
    "#,
        ParseGoal::Script,
        &["true", "true"],
    );
}

#[test]
fn literal_and_class_initializers_define_own_properties() {
    assert_output(
        r#"
        let calls = 0;
        const prototypeWithSetter = { set x(value) { calls++; } };
        const o = { __proto__: prototypeWithSetter, x: 3 };
        class Base {}
        Object.defineProperty(Base, 'm', { value: function() { return 1; }, writable: false, configurable: true });
        class Child extends Base { static m() { return 2; } }
        console.log(calls, o.x, Child.m(), Object.getOwnPropertyDescriptor(Child, 'm').enumerable);
        const proto = { p: 5 }; const plain = { __proto__: proto, x: 8 };
        const computed = { ['__proto__']: 4 };
        console.log(plain.p, plain.x, computed['__proto__'], calls);
    "#,
        ParseGoal::Script,
        &["0 3 2 false", "5 8 4 0"],
    );
}

#[test]
fn prototype_initializer_preserves_prior_own_data_properties() {
    assert_output(
        r#"
        const parent = { inherited: 7 };
        const direct = { ['__proto__']: 1, __proto__: parent, tail: 2 };
        const spread = { ...{ ['__proto__']: 3 }, __proto__: parent, tail: 4 };
        console.log(direct.__proto__, direct.inherited, direct.tail);
        console.log(spread.__proto__, spread.inherited, spread.tail);
        console.log(Object.keys(direct).join(','), Object.keys(spread).join(','));
        direct.__proto__ = 9;
        console.log(direct.__proto__, direct.inherited);
    "#,
        ParseGoal::Script,
        &["1 7 2", "3 7 4", "__proto__,tail __proto__,tail", "9 7"],
    );
}

#[test]
fn prototype_initializer_bypasses_prior_own_accessors() {
    assert_output(
        r#"
        let stored = 0;
        const object = {
            get __proto__() { return 11; },
            set __proto__(value) { stored = value; },
            __proto__: { inherited: 7 },
            tail: 2
        };
        const descriptor = Object.getOwnPropertyDescriptor(object, '__proto__');
        console.log(stored, object.__proto__, object.inherited, object.tail);
        console.log(typeof descriptor.get, typeof descriptor.set, descriptor.enumerable);
        object.__proto__ = 42;
        console.log(stored, object.__proto__, object.inherited);
    "#,
        ParseGoal::Script,
        &["0 11 7 2", "function function true", "42 11 7"],
    );
}

#[test]
fn prototype_initializer_handles_function_null_and_ignored_primitive_values() {
    assert_output(
        r#"
        let trace = '';
        const parent = function() {};
        function choose() { trace += 'p'; return parent; }
        function make() { return { __proto__: choose(), tail: (trace += 't', 42) }; }
        const object = make();
        parent.inherited = 9;
        console.log(object.inherited, object.tail, trace, Object.keys(object).join(','));
        const nullPrototype = { ['__proto__']: 3, __proto__: null, tail: 4 };
        console.log(nullPrototype.__proto__, nullPrototype.tail, Object.keys(nullPrototype).join(','));
        for (const value of [undefined, false, 7, 'ignored', Symbol('ignored')]) {
            const ignored = { ['__proto__']: 5, __proto__: value, tail: 6 };
            console.log(ignored.__proto__, ignored.tail, Object.keys(ignored).join(','));
        }
    "#,
        ParseGoal::Script,
        &[
            "9 42 pt tail",
            "3 4 __proto__,tail",
            "5 6 __proto__,tail",
            "5 6 __proto__,tail",
            "5 6 __proto__,tail",
            "5 6 __proto__,tail",
            "5 6 __proto__,tail",
        ],
    );
}

#[test]
fn primitive_property_mutations_follow_their_mode() {
    assert_output(
        r#"
        console.log((1).x = 3, delete 'ab'[0], delete 'ab'.other);
        function strict() { 'use strict';
            try { (1).x = 3; } catch (e) { console.log(e.name); }
            try { delete 'ab'[0]; } catch (e) { console.log(e.name); }
        }
        strict();
    "#,
        ParseGoal::Script,
        &["3 false true", "TypeError", "TypeError"],
    );
}

#[test]
fn directive_provenance_roundtrips_and_changes_canonical_semantics() {
    let span = SourceSpan::new(0, 12, 1, 1, 1, 13);
    let tree = |raw: &str| SyntaxTree {
        goal: ParseGoal::Script,
        span: span.clone(),
        body: vec![Statement::Expression(ExpressionStatement {
            expression: Expression::StringLiteral("use strict".into()),
            span: span.clone(),
            raw_directive: Some(raw.into()),
        })],
    };
    let strict = tree("use strict");
    let escaped = tree(r"use\x20strict");
    assert_ne!(strict.canonical_hash(), escaped.canonical_hash());
    let encoded = serde_json::to_vec(&strict).expect("serialize provenance");
    let decoded: SyntaxTree = serde_json::from_slice(&encoded).expect("deserialize provenance");
    assert_eq!(strict, decoded);
    let ordinary = CanonicalEs2020Parser
        .parse("42;", ParseGoal::Script)
        .expect("ordinary source");
    assert!(
        !serde_json::to_string(&ordinary)
            .expect("ordinary AST")
            .contains("raw_directive")
    );
}

#[test]
fn strict_and_definition_instructions_cannot_be_backversioned() {
    let mut module = lower(
        "'use strict'; const o = {}; o.x = 1; delete o.x;",
        ParseGoal::Script,
    );
    assert!(
        module
            .instructions
            .iter()
            .any(|instruction| matches!(instruction, Ir3Instruction::SetPropertyStrict { .. }))
    );
    assert!(
        module
            .instructions
            .iter()
            .any(|instruction| matches!(instruction, Ir3Instruction::DeletePropertyStrict { .. }))
    );
    module.header.schema_version = IrSchemaVersion {
        major: 0,
        minor: 19,
        patch: 0,
    };
    assert!(verify_ir3_specialization(&module).is_err());
}
