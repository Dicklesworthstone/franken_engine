//! bd-9vouw.317: an arrow function has no new.target of its own; it reads
//! the enclosing non-arrow function's (ES2020 12.3.8.1 GetNewTarget). It
//! read undefined, the new.target of the arrow's own call frame. The
//! program reads new.target through arrows, nested arrows, a derived class
//! constructor, Reflect.construct, a callback, an async arrow and an arrow
//! returned out of its constructor and called later. It also checks the
//! places where the value must stay undefined: a plain call, a function
//! expression between the constructor and the arrow, a class field
//! initializer and a generator. Node v22.2.0 gives this line; Bun 1.4.2
//! agrees.

use frankenengine_engine::parser::ParseErrorCode;
use frankenengine_engine::parser_api_stability::{parse_module, parse_script};
use frankenengine_engine::{EvalErrorCode, HybridRouter};

/// ES2020 15.1.1 and 15.2.1.1 forbid NewTarget in source-level code.
/// Arrows inherit their enclosing function environment; neither strict mode
/// nor the Module goal creates one. Computed class/method names and heritage
/// expressions are evaluated in the enclosing environment too.
#[test]
fn new_target_requires_a_function_environment_in_both_parse_goals() {
    for source in [
        "new.target;",
        "'use strict'; new.target;",
        "if (false) { new.target; }",
        "const arrow = () => new.target;",
        "const arrow = () => () => new.target;",
        "const arrow = (value = new.target) => value;",
        "const arrow = async () => new.target;",
        "const arrow = async (value = new.target) => value;",
        "const object = { [new.target]() {} };",
        "class C { [new.target]() {} }",
        "class C { [new.target] = 1; }",
        "class C extends new.target {}",
        "function f() { return new.target; } new.target;",
        "class C { field = new.target; } new.target;",
        "class C { static { new.target; } } new.target;",
    ] {
        for (goal, parsed) in [
            ("script", parse_script(source)),
            ("module", parse_module(source)),
        ] {
            let error = parsed.expect_err("new.target outside a function must fail at parse time");
            assert_eq!(
                error.code,
                ParseErrorCode::InvalidSyntax,
                "{goal}: {source}: {error}"
            );
            assert!(
                error.message.contains("new.target"),
                "{goal}: {source}: {error}"
            );
        }
    }
}

#[test]
fn function_environments_allow_new_target_without_changing_the_parse_goal() {
    for source in [
        "function f(value = new.target) { return new.target; }",
        "const f = function (value = new.target) { return new.target; };",
        "async function f(value = new.target) { return new.target; }",
        "function* f(value = new.target) { yield new.target; }",
        "async function* f(value = new.target) { yield new.target; }",
        "function f() { return () => () => new.target; }",
        "function f() { return async (value = new.target) => value; }",
        "const object = { method(value = new.target) { return () => new.target; } };",
        "const object = { get value() { return new.target; }, set value(v) { new.target; } };",
        "class C { constructor(value = new.target) { this.value = value; } }",
        "class C { method(value = new.target) { return new.target; } }",
        "class C { *method(value = new.target) { yield new.target; } }",
        "class C { field = () => new.target; static field = new.target; }",
        "class C { static { const arrow = () => new.target; } }",
        "function f() { return class extends new.target { [new.target]() {} }; }",
        "function f() { return new.target?.name; }",
    ] {
        parse_script(source).unwrap_or_else(|error| panic!("script: {source}: {error}"));
        parse_module(source).unwrap_or_else(|error| panic!("module: {source}: {error}"));
    }

    // NewTarget's function scope is independent of ImportMeta's source goal.
    for source in [
        "function f() { return [new.target, import.meta]; }",
        "class C { field = [new.target, import.meta]; }",
        "function f() { return new.target?.name ?? import.meta?.url; }",
    ] {
        parse_module(source).unwrap_or_else(|error| panic!("module: {source}: {error}"));
        let error =
            parse_script(source).expect_err("a function does not permit import.meta in scripts");
        assert_eq!(
            error.code,
            ParseErrorCode::InvalidSyntax,
            "{source}: {error}"
        );
        assert!(error.message.contains("import.meta"), "{source}: {error}");
    }
}

#[test]
fn meta_properties_require_exact_unescaped_keyword_syntax() {
    for source in [
        "function f() { return new?.target; }",
        "function f() { return new?.target?.name; }",
        "const f = function () { return () => new?.target; };",
        "class C { field = new?.target; }",
        "function f() { return new.other; }",
        "function f() { return new.\\u0074arget; }",
    ] {
        for (goal, parsed) in [
            ("script", parse_script(source)),
            ("module", parse_module(source)),
        ] {
            let error = parsed.expect_err("a meta property requires an ordinary dot");
            assert_eq!(
                error.code,
                ParseErrorCode::InvalidSyntax,
                "{goal}: {source}: {error}"
            );
        }
    }
    for source in [
        "import?.meta;",
        "import?.meta.url;",
        "function f() { return import?.meta; }",
        "import.other;",
        "import.\\u006deta;",
    ] {
        let error = parse_module(source).expect_err("only import.meta is an ImportMeta production");
        assert_eq!(
            error.code,
            ParseErrorCode::InvalidSyntax,
            "{source}: {error}"
        );
    }
}

#[test]
fn public_module_preparation_rejects_invalid_new_target_before_execution() {
    for body in [
        "new.target;",
        "const unused = () => new.target;",
        "function unused() { return new?.target; }",
        "import?.meta;",
    ] {
        let source = format!("export {{}}; console.log('must not run'); {body}");
        let error =
            HybridRouter::prepare_eval(&source).expect_err("invalid module must not compile");
        assert_eq!(error.code, EvalErrorCode::ParseFailure, "{source}: {error}");
    }
}

#[test]
fn dynamic_function_new_target_stays_valid_and_direct_eval_stays_denied() {
    let source = r#"
const F = Function('return () => new.target;');
console.log(F()() === undefined, new F()() === F);
let name = '';
try { Function('return new?.target;'); } catch (error) { name = error.name; }
console.log(name);
"#;
    let outcome = HybridRouter::default()
        .eval(source)
        .expect("contained Function must keep its own environment");
    let lines: Vec<&str> = outcome
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect();
    assert_eq!(lines, ["true true", "SyntaxError"]);

    let error = HybridRouter::prepare_eval("function F() { return eval('new.target'); } new F();")
        .expect_err("new.target parsing must not widen direct-eval authority");
    assert!(error.message.contains("runtime.eval"), "{error}");
}

#[test]
fn arrow_functions_read_the_enclosing_new_target() {
    let source = r#"
var out = [];
function n(v) { return v === undefined ? 'undefined' : typeof v === 'function' ? v.name : String(v); }
function F() { var a = () => new.target; out.push(a() === F); }
new F();
function F2() { out.push((() => () => new.target)()() === F2); }
new F2();
class C { constructor() { var a = () => new.target; out.push(a() === D); } }
class D extends C {}
new D();
function H() { return () => new.target; }
out.push(new H()() === H);
function G() { var a = () => new.target; return a(); }
out.push(n(G()));
function R() { out.push((() => new.target)() === Array); }
Reflect.construct(R, [], Array);
function U() { out.push([1].map(() => new.target === U)[0]); }
new U();
function I() { out.push(n((function () { return (() => new.target)(); })())); }
new I();
function O() { class K { f = () => new.target; } out.push(n(new K().f())); }
new O();
function* Gen() { yield (() => new.target)(); }
out.push(n(Gen().next().value));
function W() { var a = () => new.target; return a; }
var w = new W();
out.push(w() === W, w.call({}) === W);
function A2() { return () => [new.target === A2, arguments.length].join(); }
out.push(new A2(1, 2)());
function M() { this.p = (async () => new.target)(); }
new M().p.then(function (v) {
  out.push(v === M);
  console.log(out.join(' '));
});
"#;
    let outcome = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"));
    let lines: Vec<&str> = outcome
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect();
    assert_eq!(
        lines,
        [
            "true true true true undefined true true undefined undefined undefined true true true,2 true"
        ]
    );
}
