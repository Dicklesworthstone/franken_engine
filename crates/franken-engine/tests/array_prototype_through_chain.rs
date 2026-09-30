//! An object whose prototype chain goes through an array inherits the
//! Array.prototype builtins (`F.prototype = [...]`, `Object.create([])`).
//!
//! Only an array itself exposed them: the engine serves Array.prototype's
//! methods without allocating that object, and the fallback looked at the
//! root object only, so `new F().reduce(...)` was "expected function, got
//! undefined" (Test262 Array/prototype/reduce/15.4.4.21-10-6 and relatives).
//! Expected lines are Node v22.2.0's (`node -e`).

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
        "constructor_prototype_is_an_array",
        r#"function foo() {} foo.prototype = [1, 2, 3, 4]; const f = new foo(); console.log(f.reduce((a, b) => a + b, -1), f.length, 'map' in f, f.constructor === Array, Array.isArray(f));"#,
        "9 4 true true false",
    ),
    (
        "object_create_array",
        r#"const o = Object.create(['x', 'y']); console.log(o.join('-'), o.indexOf('y'), o.slice(1).length, typeof o.push);"#,
        "x-y 1 1 function",
    ),
    (
        "own_property_still_wins",
        r#"function Stack() {} Stack.prototype = []; Stack.prototype.push = function (v) { return 'custom ' + v; }; const s = new Stack(); console.log(s.push(1), typeof s.pop);"#,
        "custom 1 function",
    ),
    // The generic methods read `length` and the elements through the chain
    // ([[Get]]), not the receiver's own properties only.
    (
        "generic_methods_read_inherited_elements",
        r#"const o = Object.create(['x', 'y']); console.log(Array.prototype.join.call(o, '-'), Array.prototype.slice.call(o).length, [].concat(Array.prototype.map.call(o, (v) => v + v)).join());"#,
        "x-y 2 xx,yy",
    ),
    (
        "push_on_an_inherited_length_writes_own_properties",
        r#"function foo() {} foo.prototype = [1, 2, 3, 4]; const f = new foo(); f.push(5); console.log(f.length, Object.keys(f).join(), f.reduce((a, b) => a + b), f.lastIndexOf(2), f.includes(4));"#,
        "5 4,length 15 1 true",
    ),
    (
        "array_like_prototype",
        r#"const o = Object.create({ length: 2, 0: 'a', 1: 'b' }); console.log(Array.prototype.join.call(o), Array.from(o).join('|'));"#,
        "a,b a|b",
    ),
    (
        "hole_reads_object_prototype_index",
        r#"const a = [1, , 3]; Object.prototype[1] = 'P'; console.log(a.join('-'), a.indexOf('P')); delete Object.prototype[1];"#,
        "1-P-3 1",
    ),
];
fn console_output(source: &str) -> Result<String, String> {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "arrayproto.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .map_err(|error| format!("parse: {error:?}"))?;
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "arrayproto.js"),
        &LoweringContext::new(
            "arrayproto-trace",
            "arrayproto-decision",
            "arrayproto-policy",
        ),
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
    let mut core = InterpreterCore::new(config, "arrayproto");
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
fn array_prototype_through_the_chain_matches_node() {
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
