//! bd-9vouw.321: %GeneratorFunction%, %AsyncFunction% and
//! %AsyncGeneratorFunction% build functions from source text, called or
//! constructed, through the Function constructor's contained-codegen path.
//! They refused every call. The program checks each kind's result: its
//! calls, name, length, prototype and source text. It also checks that
//! parameters or a body which close the inner function early are a
//! SyntaxError and inject nothing. Node v22.2.0 gives this line; Bun 1.4.2
//! agrees.

use frankenengine_engine::HybridRouter;

#[test]
fn generator_and_async_function_constructors_build_functions() {
    let source = r#"
var out = [];
var GeneratorFunction = Object.getPrototypeOf(function* () {}).constructor;
var AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
var AsyncGeneratorFunction = Object.getPrototypeOf(async function* () {}).constructor;
var g = GeneratorFunction('a', 'b', 'yield a; yield a + b;');
out.push(typeof g, g.name, g.length, [...g(1, 2)].join(','), Object.getPrototypeOf(g) === GeneratorFunction.prototype);
out.push(JSON.stringify(g.toString()));
var g2 = new GeneratorFunction('yield 7');
out.push(g2().next().value);
var af = AsyncFunction('x', 'return await x * 2;');
out.push(af.name, af.length, Object.getPrototypeOf(af) === AsyncFunction.prototype);
var ag = new AsyncGeneratorFunction('yield 1; yield 2;');
out.push(Object.getPrototypeOf(ag) === AsyncGeneratorFunction.prototype);
function attempt(f) { try { f(); return 'ok'; } catch (e) { return e.constructor.name; } }
out.push(attempt(function () { GeneratorFunction('}; out.push("injected"); function* x() {'); }));
out.push(attempt(function () { AsyncFunction('a) {}; out.push("injected"); (async function (b', ''); }));
Promise.all([af(21), (async function () { var r = []; for await (var v of ag()) r.push(v); return r.join(','); })()]).then(function (values) {
  out.push(values.join('/'));
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
            "function anonymous 2 1,3 true \"function* anonymous(a,b\\n) {\\nyield a; yield a + b;\\n}\" 7 anonymous 1 true true SyntaxError SyntaxError 42/1,2"
        ]
    );
}
