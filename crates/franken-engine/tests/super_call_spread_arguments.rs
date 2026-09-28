//! ES2020 12.3.7.1 SuperCall: `super(...args)` spreads its argument list into
//! the parent constructor, like any call. FrankenEngine's ConstructSuper took a
//! fixed argument count and a spread element evaluated to its inner value, so
//! the whole array arrived as the FIRST argument: `super(...args)` in
//! `class B extends A { constructor(...args) { super(...args); } }` gave A
//! `a = [1, 2, 3]`, Error subclasses lost their message, and Array subclasses
//! came out empty. Expected string is Node v22.2.0's output.

use frankenengine_engine::HybridRouter;

#[test]
fn super_call_spreads_its_arguments_into_the_parent_constructor() {
    let source = "const out = [];\n\
                  class A { constructor(a, b, c) { this.v = [a, b, c].join('|'); this.nt = new.target.name; } }\n\
                  class B extends A { constructor(...args) { super(...args); } }\n\
                  class C extends A { constructor(x, ...rest) { const r = super(x * 10, ...rest, 'tail'); this.same = r === this; } }\n\
                  class D extends B { constructor(...args) { super(...args.reverse()); } }\n\
                  const b = new B(1, 2, 3), c = new C(1, 2), d = new D(1, 2, 3);\n\
                  out.push(b.v, b.nt, b instanceof B, c.v, c.nt, c.same, d.v, d.nt, d instanceof B);\n\
                  class E extends Error { constructor(...args) { super(...args); this.name = 'E'; } }\n\
                  const e = new E('boom');\n\
                  out.push(e.message, e instanceof E, e instanceof Error, String(e));\n\
                  class L extends Array { constructor(...items) { super(...items); } }\n\
                  const l = new L(1, 2, 3);\n\
                  out.push(l.length, l[2], l instanceof L, Array.isArray(l));\n\
                  class M extends Map { constructor(...args) { super(...args); } }\n\
                  const m = new M([[1, 'one']]);\n\
                  out.push(m.get(1), m instanceof M);\n\
                  class N extends A { constructor() { super(...[]); } }\n\
                  out.push(new N().v);\n\
                  out.join(' ');";
    let value = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .value;
    assert_eq!(
        value,
        "1|2|3 B true 10|2|tail C true 3|2|1 D true boom true true E: boom 3 3 true true one true ||"
    );
}
