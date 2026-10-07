//! bd-9vouw.304: each class member inherits the enclosing scope's markers
//! for the names its own code mentions, plus the class-level names (the
//! class name and the superclass expression), not for every name the whole
//! class mentions.
//!
//! Every method, accessor and field initializer was prepared with the
//! class-wide mention set, so a class of N members lowered in O(N^2): 2,000
//! private fields compiled in 5 s, and the Test262 start-unicode-*-class
//! tests (3,000 to 6,000 private fields) timed out. The program below reaches
//! every kind of name through members that do not mention it: an outer
//! variable, the class name, a private field declared by another member, a
//! private method, a private `in` check, a static private field, `super`, a
//! computed key and a class expression's own name. Node v22.2.0 gives this
//! value; Bun 1.4.2 agrees.
//!
//! No-claim: lowering time is not asserted here (the commit message records
//! the measurement); this test pins what per-member mentions must still
//! resolve.

use frankenengine_engine::HybridRouter;

fn eval(source: &str) -> String {
    HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .value
}

#[test]
fn members_reach_names_that_only_other_members_or_the_class_mention() {
    let mut source = String::from(
        "var outer = 'o';\n\
         let counter = 0;\n\
         const K = 'computed';\n\
         class Base { base() { return 'b'; } }\n\
         class C extends Base {\n",
    );
    source.extend((0..1000).map(|i| format!("  #f{i} = {i};\n  p{i} = {i};\n")));
    source.push_str(
        "  [K] = K + outer;\n\
         \x20 #secret = outer;\n\
         \x20 late = this.#secret + C.name + this.p999;\n\
         \x20 static #count = 0;\n\
         \x20 static make() { return new C(); }\n\
         \x20 #hidden() { return ++counter; }\n\
         \x20 has(o) { return #secret in o; }\n\
         \x20 call() { return this.#hidden() + this.#f999; }\n\
         \x20 sup() { return super.base(); }\n\
         \x20 arrow() { return () => this.#secret + outer; }\n\
         \x20 static bump() { return ++C.#count; }\n\
         }\n\
         const D = class Named extends C { extra = Named.name + this.#own(); #own() { return outer; } };\n\
         const c = C.make();\n\
         const d = new D();\n\
         [c.computed, c.late, c.has(c), c.has({}), c.call(), c.sup(), c.arrow()(), C.bump(), C.bump(), d.extra, d.call(), Object.keys(d).length].join(' ');",
    );
    assert_eq!(
        eval(&source),
        "computedo oC999 true false 1000 b oo 1 2 Namedo 1001 1003"
    );
}
