//! Property reads on primitive values go through their prototype chain
//! (ES2020 6.2.4.8 GetValue: ToObject(base).[[Get]](P, base)).
//!
//! Before: any property read on a boolean was an internal type error
//! (`true.toString()`, `flag.constructor`, even `true.foo`); on strings,
//! numbers and BigInts only a static table of builtin methods answered, so
//! members a program added to `String.prototype`/`Number.prototype`
//! (polyfills), `constructor`, and Object.prototype members
//! (`(1).hasOwnProperty`) were missing. Found through lodash 4.17.21, whose
//! bundle stopped at a boolean property read.
//!
//! Each program runs through the parser, the lowering and the interpreter;
//! the expected line is what Node v22.2.0 prints for the same program
//! (`node -e`). Every run also checks the memory-accounting invariant.

#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

/// (name, program, Node v22.2.0 output)
const CASES: &[(&str, &str, &str)] = &[
    (
        "boolean_methods",
        r#"console.log(true.toString(), false.toString(), true.valueOf(), (1 > 2).valueOf(), typeof true.valueOf());"#,
        "true false true false boolean",
    ),
    (
        "boolean_constructor_and_missing",
        r#"const v = false; console.log(v.constructor === Boolean, v.constructor.name, v.foo, true['toString']());"#,
        "true Boolean undefined true",
    ),
    (
        "boolean_prototype_user_method",
        r#"Boolean.prototype.flip = function () { return !this.valueOf(); }; console.log(true.flip(), false.flip());"#,
        "false true",
    ),
    (
        "boolean_prototype_itself",
        r#"console.log(Boolean.prototype.valueOf(), Boolean.prototype.toString());"#,
        "false false",
    ),
    (
        "boolean_wrong_receiver",
        r#"try { Boolean.prototype.toString.call(1); console.log('no throw'); } catch (e) { console.log(e instanceof TypeError); }"#,
        "true",
    ),
    (
        "number_user_method",
        r#"Number.prototype.twice = function () { return this * 2; }; console.log((3).twice(), 2.5.twice());"#,
        "6 5",
    ),
    (
        "string_user_method",
        r#"String.prototype.shout = function () { return this.toUpperCase() + '!'; }; console.log('hi'.shout(), 'hi'.length, 'hi'[1]);"#,
        "HI! 2 i",
    ),
    (
        "bigint_user_method",
        r#"BigInt.prototype.half = function () { return this / 2n; }; console.log(String(10n.half()), (7n).toString());"#,
        "5 7",
    ),
    (
        "user_override_wins",
        r#"const orig = String.prototype.trim; String.prototype.trim = function () { return '[' + orig.call(this) + ']'; }; console.log('  a  '.trim());"#,
        "[a]",
    ),
    (
        "polyfill_guard",
        r#"if (!String.prototype.padStart) { console.log('missing'); } else { console.log('present', 'x'.padStart(3, '-')); }"#,
        "present --x",
    ),
    (
        "constructors",
        r#"console.log((1).constructor === Number, 'x'.constructor === String, (1n).constructor === BigInt, true.constructor === Boolean, (1).constructor.name);"#,
        "true true true true Number",
    ),
    (
        "object_prototype_members",
        r#"Object.prototype.tag = 'T'; console.log((1).tag, 'x'.tag, true.tag, (5n).tag);"#,
        "T T T T",
    ),
    (
        "has_own_property",
        r#"console.log((1).hasOwnProperty('x'), 'ab'.hasOwnProperty('length'), 'ab'.hasOwnProperty('1'), 'ab'.hasOwnProperty('2'), true.hasOwnProperty('valueOf'));"#,
        "false true true false false",
    ),
    (
        "is_prototype_of_and_tostring",
        r#"console.log(Object.prototype.toString.call(true), String.prototype.isPrototypeOf('x'), (7).toString(2), 'q'.toString());"#,
        "[object Boolean] false 111 q",
    ),
    (
        "getter_on_prototype",
        r#"Object.defineProperty(Number.prototype, 'sq', { get() { return this * this; }, configurable: true }); console.log((4).sq, 1.5.sq);"#,
        "16 2.25",
    ),
    (
        "symbol_members",
        r#"const s = Symbol('d'); console.log(s.description, s.toString());"#,
        "d Symbol(d)",
    ),
    (
        "lodash_like_checks",
        r#"function isPrototype(value) { const Ctor = value && value.constructor; const proto = (typeof Ctor == 'function' && Ctor.prototype) || Object.prototype; return value === proto; } console.log(isPrototype(true), isPrototype(1), isPrototype('s'), isPrototype(Object.prototype));"#,
        "false false false true",
    ),
    (
        "string_iteration_unchanged",
        r#"let out = ''; for (const c of 'abc') out += c.toUpperCase(); console.log(out, 'abc'.split('').reverse().join(''));"#,
        "ABC cba",
    ),
];

fn console_output(source: &str) -> Result<String, String> {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "primitive.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .map_err(|error| format!("parse: {error:?}"))?;
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "primitive.js"),
        &LoweringContext::new("primitive-trace", "primitive-decision", "primitive-policy"),
    )
    .map_err(|error| format!("lower: {error:?}"))?
    .ir3;
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = [
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
        RuntimeCapability::Console,
    ]
    .into_iter()
    .collect();
    let mut core = InterpreterCore::new(config, "primitive");
    let result = core.execute(&module);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes(),
        "memory accounting drift: {source}"
    );
    let result = result.map_err(|error| format!("{error:?}"))?;
    Ok(result
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect::<Vec<_>>()
        .join("\n"))
}

#[test]
fn primitive_property_reads_match_node() {
    let mut mismatches = Vec::new();
    for (name, source, node) in CASES {
        match console_output(source) {
            Ok(output) if output == *node => {}
            other => mismatches.push(format!("{name}: node {node:?}, got {other:?}")),
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} of {} programs differ from Node:\n{}",
        mismatches.len(),
        CASES.len(),
        mismatches.join("\n")
    );
}
