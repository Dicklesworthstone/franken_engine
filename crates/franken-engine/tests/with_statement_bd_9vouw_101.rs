//! bd-9vouw.101: `with` statements (ES2020 13.11).
//!
//! The lowering refused every program containing `with`
//! (FE-PARSER-GAP-WITH-0001). String templates compile to `with (obj) {...}`
//! bodies: underscore's and lodash's `_.template`, and EJS by default. Each
//! `with` is now rewritten ahead of lowering: the body's free names resolve
//! through the object first, following HasBinding with @@unscopables. The
//! object is the receiver of calls it supplies, a `var` initializer assigns
//! through it, and closures keep it. Expected lines are Node v22.2.0's output
//! for the same program (`node file.js`).
//!
//! No-claim: destructuring `var` declarations and destructuring for-in/for-of
//! heads that bind through the object are still refused. `arguments` is never
//! looked up in the object. Array.prototype[@@unscopables] is the object
//! `with (array)` consults (bd-9vouw.341). The franken-core twin still
//! refuses `with`.

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
        "basics",
        r#"var o = { a: 1, f: function () { return this === o; } };
var b = 10, out = [];
with (o) {
  out.push(a, b, f(), typeof a, typeof zz, typeof b);
  a = 2; b = 20;
  var c = 3;
  out.push(o.a, b, c);
}
out.push(typeof o.c, c);
console.log(out.join(' '));"#,
        r#"1 10 true number undefined number 2 20 3 undefined 3"#,
    ),
    (
        "template",
        r#"var render = new Function('obj', "var __t,__p='',__j=Array.prototype.join,print=function(){__p+=__j.call(arguments,'');};\nwith(obj||{}){\n__p+='Hello '+((__t=( name ))==null?'':__t)+'! ';\n for (var i = 0; i < items.length; i++) { __p+='<'+((__t=( items[i] ))==null?'':__t)+'>'; }\n print(' done');\n}\nreturn __p;");
console.log(render({name: 'World', items: [1, 2]}));"#,
        r#"Hello World! <1><2> done"#,
    ),
    (
        "nested",
        r#"var x = 'outer';
var inner = { y: 'iy' }, outerObj = { x: 'ox', z: 'oz' };
var r = [];
with (outerObj) { with (inner) { r.push(x, y, z); x = 'set'; } }
r.push(outerObj.x, x);
console.log(r.join(' '));"#,
        r#"ox iy oz set outer"#,
    ),
    (
        "unscopables",
        r#"var r = [];
var o = { a: 1, b: 2 };
o[Symbol.unscopables] = { b: true };
var b = 'outer b';
with (o) { r.push(a, b); }
var arr = [1, 2];
with (arr) { r.push(length, typeof push); }
console.log(r.join(' '));"#,
        r#"1 outer b 2 function"#,
    ),
    (
        "closures",
        r#"var o = { n: 1, get() { return this.n; } };
var fns;
with (o) { fns = [function () { return n; }, () => get()]; }
o.n = 5;
console.log(fns[0](), fns[1]());"#,
        r#"5 5"#,
    ),
    (
        "toobject",
        r#"var e; try { with (null) {} } catch (err) { e = err instanceof TypeError; }
var s; with (5) { s = toFixed(1); }
console.log(e, s);"#,
        r#"true 5.0"#,
    ),
    (
        "forin",
        r#"var o = { k: 'initial' }, seen = [];
with (o) { for (var k in { p: 1, q: 2 }) seen.push(k); }
console.log(seen.join(','), o.k, typeof k);"#,
        r#"p,q q undefined"#,
    ),
    (
        "declared_inside",
        r#"var o = { v: 'object v', w: 'object w' }, r = [];
function f() {
  with (o) {
    let v = 'block v';
    r.push(v, w);
    function w2() { var w = 'local w'; return w; }
    r.push(w2());
    try { throw 'thrown'; } catch (w) { r.push(w); }
  }
}
f();
console.log(r.join(' '));"#,
        r#"block v object w local w thrown"#,
    ),
    (
        "compound_and_update",
        r#"var o = { n: 1 }, m = 10;
with (o) { n += 5; n++; m *= 2; ++m; }
console.log(o.n, m);"#,
        r#"7 21"#,
    ),
    (
        "array_unscopables",
        r#"var keys = 'outer keys', values = 'outer values', r = [];
var arr = [1, 2];
with (arr) { r.push(typeof keys, keys, values, length, typeof push, typeof includes, typeof at); }
console.log(r.join(' '));"#,
        r#"string outer keys outer values 2 function undefined undefined"#,
    ),
];

fn console_output(source: &str) -> Result<String, String> {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "with.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .map_err(|error| format!("parse: {error:?}"))?;
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "with.js"),
        &LoweringContext::new("with-trace", "with-decision", "with-policy"),
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
    let mut core = InterpreterCore::new(config, "with");
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
fn with_statements_match_node() {
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

/// A destructuring `var` that would bind through the object is refused
/// with its own diagnostic, not run with a wrong binding.
#[test]
fn destructuring_var_inside_with_is_refused() {
    let error = console_output("var o = {}; with (o) { var { a } = { a: 1 }; }")
        .expect_err("destructuring var inside with must be refused");
    assert!(error.contains("FE-PARSER-GAP-WITH-0002"), "{error}");
}

/// ES2020 13.11.1: a `with` body is a Statement, so a declaration there (or a
/// labelled function) is a SyntaxError even in sloppy code, as in Node
/// v22.2.0 (Test262 statements/with/decl-async-gen.js). A `var` body still
/// runs.
#[test]
fn declarations_are_not_with_bodies() {
    for source in [
        "with ({}) function f() {}",
        "with ({}) async function* g() {}",
        "with ({}) class C {}",
        "with ({}) let [a] = [1];",
        "with ({}) L: function f() {}",
    ] {
        let error = console_output(source).expect_err(source);
        assert!(
            error.contains("is not allowed in statement position"),
            "{source}: {error}"
        );
    }
    assert_eq!(
        console_output("var o = { a: 1 }; with (o) var b = a + 1; with (o) console.log(a, b);")
            .as_deref(),
        Ok("1 2")
    );
}

fn lowering_error(source: &str) -> Option<String> {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "with.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("parse");
    lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "with.js"),
        &LoweringContext::new("with-trace", "with-decision", "with-policy"),
    )
    .err()
    .map(|error| format!("{error:?}"))
}

/// A secret read in a `with` body keeps its label to a console sink: through
/// the object, when the object's property shadows a local, and when the value
/// leaves the body by assignment. `console.log` inside the body keeps its
/// source form as one branch, so the lowering still recognizes the sink. The
/// secret is an entropy read, as in ifc_flow_label_ceiling_bd_9vouw_1.
#[test]
fn secrets_read_in_a_with_body_cannot_reach_the_console() {
    const SECRET: &str = "const crypto = require('crypto'); const secret = crypto.randomUUID(); ";
    for (name, program) in [
        (
            "sink_inside_body",
            "var holder = { x: secret }; with (holder) { console.log(x); }",
        ),
        (
            "object_property_shadows_a_public_local",
            "var x = 'public'; with ({ x: secret }) { console.log(x); }",
        ),
        (
            "value_leaves_the_body_by_assignment",
            "var holder = { x: secret }, out; with (holder) { out = x; } console.log(out);",
        ),
    ] {
        let error = lowering_error(&format!("{SECRET}{program}"))
            .unwrap_or_else(|| panic!("{name}: a secret reached the console sink"));
        assert!(
            error.contains("UnauthorizedFlow")
                && (error.contains("source_label: Secret")
                    || error.contains("source_label: TopSecret"))
                && error.contains("sink_clearance: Internal"),
            "{name}: {error}"
        );
    }
    // Control: without a secret in the program the same shape lowers and runs.
    assert_eq!(
        console_output("var x = 'public'; with ({ y: 1 }) { console.log(x); }").as_deref(),
        Ok("public")
    );
}

/// Names in a `with` body keep the ambient-authority check of the bare
/// identifier: the object cannot make `require` or `fetch` a benign name.
#[test]
fn with_body_names_keep_their_ambient_authority_checks() {
    for program in [
        "var o = {}; with (o) { require('fs'); }",
        "var o = { fetch: 1 }; with (o) { fetch('http://example.invalid/'); }",
    ] {
        let error = lowering_error(program)
            .unwrap_or_else(|| panic!("`{program}` lowered without an authority check"));
        assert!(
            error.contains("AmbientAuthorityViolation"),
            "{program}: {error}"
        );
    }
}
