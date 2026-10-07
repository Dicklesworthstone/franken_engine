//! bd-9vouw.326: `new F(...)` for a subclass F of Function,
//! GeneratorFunction or AsyncFunction is the function built from source
//! text with F.prototype as its [[Prototype]] (ES2020 19.2.1.1.1 step 21).
//! The builtin construct path refused it, wanting an object result. The
//! program calls each instance and checks instanceof, getPrototypeOf, a
//! subclass constructor that sets a property after super(), and that plain
//! Function construction and calls keep Function.prototype. Node v22.2.0
//! gives this line; Bun 1.4.2 agrees.

use frankenengine_engine::HybridRouter;

#[test]
fn function_constructor_subclasses_build_functions() {
    let source = r#"
var out = [];
class F extends Function {}
var f = new F('a', 'b', 'return a + b');
out.push(typeof f, f(2, 3), f instanceof F, f instanceof Function, Object.getPrototypeOf(f) === F.prototype, f.length, f.name);
out.push(Object.getPrototypeOf(new Function('return 1')) === Function.prototype, Object.getPrototypeOf(Function('return 1')) === Function.prototype);
class G extends Function { constructor(...args) { super(...args); this.tag = 'g'; } }
var g = new G('return 5');
out.push(g(), g.tag, g instanceof G, Object.getPrototypeOf(G.prototype) === Function.prototype);
var GeneratorFunction = Object.getPrototypeOf(function* () {}).constructor;
class GF extends GeneratorFunction {}
var gf = new GF('yield 1; yield 2;');
out.push(gf instanceof GF, gf instanceof GeneratorFunction, [...gf()].join(), Object.getPrototypeOf(gf) === GF.prototype, gf() instanceof gf);
var AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
class AF extends AsyncFunction {}
var af = new AF('return 9');
out.push(af instanceof AF);
af().then(function (v) { out.push(v); console.log(out.join(' ')); });
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
            "function 5 true true true 2 anonymous true true 5 g true true true true 1,2 true true true 9"
        ]
    );
}
