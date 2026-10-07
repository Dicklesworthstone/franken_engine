//! An anonymous function, arrow or class bound directly to a name takes that
//! name (ES2020 NamedEvaluation): `var f = function () {}` has
//! `f.name === "f"`.
//!
//! Every such definition used to read `""` (a class read `"anonymous"`), and
//! generator and async functions had no `name` or `length` at all. Code that
//! identifies callbacks, handlers or components by `fn.name` saw empty names.
//!
//! Naming is display-only. Unlike `function f() {}`, the definition gets no
//! self binding, so its body still sees the outer variable after that is
//! reassigned. Computed object keys (`{ [k]: function () {} }`) are not named
//! yet; their name is only known at run time.
//!
//! Expected strings are what Node v22.2.0 prints for `String(<program>)`.
//!
//! No mocks: real source through the public `HybridRouter::eval` path.

use frankenengine_engine::HybridRouter;

fn eval_to_string(source: &str) -> String {
    match HybridRouter::default().eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERROR: {err:?}"),
    }
}

fn check(source: &str, node: &str) {
    assert_eq!(
        eval_to_string(source),
        node,
        "`{source}` must match Node v22.2.0"
    );
}

#[test]
fn declarations_and_assignments_name_anonymous_definitions() {
    check(
        "var f = function () {}; let a = () => 1; const c = class {}; \
         var g = function* () {}; var af = async function () {}; \
         var ag = async function* () {}; var aa = async () => 1; \
         [f.name, a.name, c.name, g.name, af.name, ag.name, aa.name].join()",
        "f,a,c,g,af,ag,aa",
    );
    check(
        "var f; f = function () {}; var a; a = () => 1; var c; c = class {}; \
         var h = null; h ||= function () {}; var n; n ??= () => 2; \
         [f.name, a.name, c.name, h.name, n.name].join()",
        "f,a,c,h,n",
    );
}

#[test]
fn object_literal_properties_name_their_values() {
    check(
        "var o = { m: function () {}, a: () => 1, c: class {}, \"a b\": function () {}, \
         5: function () {}, g: function* () {} }; \
         [o.m.name, o.a.name, o.c.name, o[\"a b\"].name, o[5].name, o.g.name].join(\"|\")",
        "m|a|c|a b|5|g",
    );
}

#[test]
fn destructuring_and_parameter_defaults_name_their_values() {
    check(
        "var { x = function () {} } = {}; var [y = () => 1] = []; \
         let { z: w = class {} } = {}; function p(q = function () {}) { return q.name; } \
         var r = []; for (const [v = () => 0] of [[]]) r.push(v.name); \
         [x.name, y.name, w.name, p(), r[0]].join()",
        "x,y,w,q,v",
    );
    check(
        "var s, t; ({ s = function () {} } = {}); [t = class {}] = []; [s.name, t.name].join()",
        "s,t",
    );
}

#[test]
fn only_direct_anonymous_definitions_are_named() {
    check(
        "var f = (0, function () {}); var g = true ? function () {} : 0; \
         var h = function named() {}; var o = {}; o.p = function () {}; \
         var k = [function () {}][0]; \
         JSON.stringify([f.name, g.name, h.name, o.p.name, k.name])",
        "[\"\",\"\",\"named\",\"\",\"\"]",
    );
}

#[test]
fn inferred_names_create_no_self_binding() {
    check(
        "var f = function () { return f; }; var g = f; f = 1; \
         var c = class { m() { return c; } }; var d = c; c = 2; \
         [g(), new d().m()].join()",
        "1,2",
    );
}

#[test]
fn generator_and_async_functions_have_name_and_length() {
    check(
        "function* gen(a, b) {} async function af(x) {} async function* ag() {} \
         var o = { *m() {}, async n(y) {} }; \
         [gen.name, gen.length, af.name, af.length, ag.name, o.m.name, o.n.name, \
         o.n.length].join()",
        "gen,2,af,1,ag,m,n,1",
    );
}

/// bd-9vouw.237: an object literal entry whose key is computed names an
/// anonymous function, arrow, generator, async arrow or class by the key's
/// value at run time (a symbol by its description in brackets, a symbol
/// without one by the empty string); a named function keeps its name, a
/// non-function value is untouched, and the name is non-writable,
/// non-enumerable and configurable. Node v22.2.0 gives this value; Bun 1.4.2
/// agrees.
#[test]
fn computed_object_keys_name_anonymous_definitions_bd_9vouw_237() {
    check(
        "var s = Symbol('d'), anon = Symbol(), k = 'x' + 1;\nvar o = {\n  [k]: function () {},\n  [s]: () => 0,\n  [anon]: function* () {},\n  ['as' + 'ync']: async () => 1,\n  [k + 'c']: class {},\n  [k + 'n']: function named() {},\n  plain: function () {},\n  [k + 'v']: 5,\n};\nvar d = Object.getOwnPropertyDescriptor(o[s], 'name');\nJSON.stringify([o.x1.name, o[s].name, o[anon].name, o.async.name, o.x1c.name, o.x1n.name, o.plain.name, o.x1v,\n  d.writable, d.enumerable, d.configurable, Object.keys(o).join()]);\n",
        r#"["x1","[d]","","async","x1c","named","plain",5,false,false,true,"x1,async,x1c,x1n,plain,x1v"]"#,
    );
}

/// bd-9vouw.237: a class field with a computed key names an anonymous
/// function, arrow or class initializer by the key's value when the field is
/// defined, static or instance ("[desc]" for a symbol); a named function, a
/// non-computed field (named at lowering) and a number are unchanged. Node
/// v22.2.0 gives this value; Bun 1.4.2 agrees.
#[test]
fn computed_class_fields_name_anonymous_initializers_bd_9vouw_237() {
    check(
        "var s = Symbol('sym'), k = 'f' + 1;\nclass C {\n  static [k] = () => 1;\n  static [s] = function () {};\n  [k + 'i'] = class {};\n  [s] = function named() {};\n  plain = () => 2;\n  [k + 'n'] = 5;\n}\nvar c = new C();\nJSON.stringify([C.f1.name, C[s].name, c.f1i.name, c[s].name, c.plain.name, c.f1n, Object.getOwnPropertyDescriptor(C.f1, 'name').writable]);\n",
        r#"["f1","[sym]","f1i","named","plain",5,false]"#,
    );
}
