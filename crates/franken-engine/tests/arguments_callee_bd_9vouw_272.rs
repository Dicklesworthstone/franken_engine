#![forbid(unsafe_code)]

//! bd-9vouw.272 (arguments objects): no arguments object had a `callee`,
//! so the legacy recursion idiom `arguments.callee(n - 1)` failed in sloppy
//! code, and strict or non-simple-parameter functions read undefined
//! instead of throwing; %ThrowTypeError% did not exist.

use frankenengine_engine::HybridRouter;
use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::ir_contract::{Ir0Module, Ir3Module};
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions};

/// A sloppy function with a simple parameter list (declaration,
/// expression, object method) gets `callee` as a writable, non-enumerable,
/// configurable data property after its indices and `length`; a strict
/// function, a class method, and a sloppy function with a default,
/// destructuring or rest parameter get the %ThrowTypeError% accessor (get
/// and set, neither enumerable nor configurable), so reading `callee`
/// throws a TypeError. %ThrowTypeError% is one frozen, non-extensible
/// function per realm named "" with length 0 and no own `caller` or
/// `arguments`; an arrow reads its enclosing function's arguments object.
/// Expected lines are Node v22.2.0's output, captured programmatically.
///
/// No-claim: assigning to a strict `callee` (V8 throws for a plain
/// assignment but not for Reflect.set, so the oracle is inconsistent);
/// a sloppy generator's arguments object has no `callee`; functions' own
/// `caller`/`arguments` and Function.prototype's accessors are not modelled
/// yet; the indices are not mapped to the parameters (bd-9vouw.281).
#[test]
fn arguments_callee_matches_node_bd_9vouw_272() {
    let source = r#"function k(f) { try { var v = f(); return v === undefined ? 'undefined' : String(v); } catch (e) { return e.constructor.name; } }
function desc(o, key) { var d = Object.getOwnPropertyDescriptor(o, key); if (!d) return 'none'; return ('value' in d ? 'data' : 'accessor') + (d.writable ? 'w' : '') + (d.enumerable ? 'e' : '') + (d.configurable ? 'c' : ''); }
function sloppy(a, b) { return arguments; }
var sa = sloppy(1, 2);
console.log(sa.callee === sloppy, desc(sa, 'callee'), Object.getOwnPropertyNames(sa).join(), Object.keys(sa).join(), JSON.stringify(sa));
console.log((function (n) { return n <= 1 ? 1 : n * arguments.callee(n - 1); })(5));
var o = { m: function () { return arguments.callee; }, s() { return arguments.callee; } };
console.log(o.m() === o.m, o.s() === o.s);
function strict() { 'use strict'; return arguments; }
function defaults(a = 1) { return arguments; }
function destructured({ a }) { return arguments; }
function rest(...r) { return arguments; }
var unmapped = [strict(1), defaults(), destructured({}), rest()];
console.log(unmapped.map(function (args) { return desc(args, 'callee') + ':' + k(function () { return args.callee; }); }).join(' '));
var thrower = Object.getOwnPropertyDescriptor(strict(), 'callee').get;
var d2 = Object.getOwnPropertyDescriptor(defaults(), 'callee');
console.log(typeof thrower, thrower === Object.getOwnPropertyDescriptor(strict(), 'callee').set, thrower === d2.get, thrower === d2.set, k(function () { return thrower(); }));
console.log(JSON.stringify(thrower.name), thrower.length, desc(thrower, 'name'), desc(thrower, 'length'), Object.isFrozen(thrower), Object.isExtensible(thrower), Object.getPrototypeOf(thrower) === Function.prototype, Object.prototype.hasOwnProperty.call(thrower, 'caller'), Object.prototype.hasOwnProperty.call(thrower, 'arguments'), Object.getOwnPropertyNames(thrower).join());
class C { m() { return arguments; } }
console.log(desc(new C().m(), 'callee'), k(function () { return new C().m().callee; }));
console.log(k(function () { return (function () { 'use strict'; return arguments.callee; })(); }), (function () { return typeof arguments.callee; })());
var arrowOuter = function () { return (() => arguments.callee)(); };
console.log(arrowOuter() === arrowOuter);
"#;
    let lines: Vec<String> = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .console_output
        .into_iter()
        .map(|entry| entry.message)
        .collect();
    assert_eq!(
        lines,
        [
            "true datawc 0,1,length,callee 0,1 {\"0\":1,\"1\":2}",
            "120",
            "true true",
            "accessor:TypeError accessor:TypeError accessor:TypeError accessor:TypeError",
            "function true true true TypeError",
            "\"\" 0 data data true false true false false length,name",
            "accessor TypeError",
            "TypeError function",
            "true",
        ]
    );
}

fn lower(source: &str, goal: ParseGoal) -> Ir3Module {
    let tree = CanonicalEs2020Parser
        .parse_with_options(source, goal, &ParserOptions::default())
        .expect("the source parses");
    lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "sloppy-functions.js"),
        &LoweringContext::new("sloppy-trace", "sloppy-decision", "sloppy-policy"),
    )
    .expect("the source lowers")
    .ir3
}

/// The IR3 entry of the function named `name`: `Some(simple parameter
/// list)` when its code is sloppy, `None` when strict.
fn sloppy_entry(ir3: &Ir3Module, name: &str) -> Option<bool> {
    let index = ir3
        .function_table
        .iter()
        .position(|desc| desc.name.as_deref() == Some(name))
        .unwrap_or_else(|| panic!("no function named {name}"));
    ir3.sloppy_functions
        .get(&u32::try_from(index).expect("small function table"))
        .copied()
}

/// bd-9vouw.272: lowering records which functions are sloppy, and whether
/// their parameter list is simple, from the parser's strictness: the
/// directive prologue, the module goal and class bodies.
#[test]
fn ir3_records_sloppy_functions_and_simple_parameter_lists_bd_9vouw_272() {
    let source = concat!(
        "function simple(a, b) {}\n",
        "function defaulted(a = 1) {}\n",
        "function rested(...r) {}\n",
        "function patterned({ a }) {}\n",
        "function directive() { 'use strict'; }\n",
        "function outer() { 'use strict'; function inner(a) {} return inner; }\n",
    );
    let script = lower(source, ParseGoal::Script);
    assert_eq!(sloppy_entry(&script, "simple"), Some(true));
    assert_eq!(sloppy_entry(&script, "defaulted"), Some(false));
    assert_eq!(sloppy_entry(&script, "rested"), Some(false));
    assert_eq!(sloppy_entry(&script, "patterned"), Some(false));
    assert_eq!(sloppy_entry(&script, "directive"), None);
    assert_eq!(sloppy_entry(&script, "inner"), None);
    let module = lower(source, ParseGoal::Module);
    assert!(module.sloppy_functions.is_empty());
    let class = lower("class K { method(a) {} }", ParseGoal::Script);
    assert!(class.sloppy_functions.is_empty());
}
