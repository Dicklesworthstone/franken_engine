//! bd-9vouw.152: `new F()` for an ordinary function whose prototype
//! inherits from Array.prototype makes an ordinary object (ES2020 9.1.13).
//!
//! The engine made an Array exotic object, so `Array.isArray` was true and
//! `this[this.length] = x; this.length++` counted every element twice
//! (cytoscape's collections). Expected strings are Node v22.2.0's output for
//! the same programs.

use frankenengine_engine::HybridRouter;

fn eval(source: &str) -> String {
    HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}\nsource: {source}"))
        .value
}

/// new F() with F.prototype = Object.create(Array.prototype) is an ordinary object: length is a plain property.
#[test]
fn array_like_es5_array_like_class() {
    let source = "var C = function C() { this.length = 0; }; C.prototype = Object.create(Array.prototype);\n\
         C.prototype.add = function (x) { this[this.length] = x; this.length++; return this; };\n\
         var c = new C().add('a').add('b');\n\
         var d = new C(); d[3] = 'z';\n\
         [Array.isArray(c), c.length, Array.prototype.slice.call(c).join('|'), c.map(function (x) { return x + '!'; }).join(),\n\
          d.length, Object.keys(d).join(), JSON.stringify(c), c instanceof Array, Object.prototype.toString.call(c)].join(' ');";
    assert_eq!(
        eval(source),
        "false 2 a|b a!,b! 0 3,length {\"0\":\"a\",\"1\":\"b\",\"length\":2} true [object Object]"
    );
}

/// A class extending Array still constructs a real array through super().
#[test]
fn array_like_class_extends_array_stays_an_array() {
    let source = "class L extends Array { last() { return this[this.length - 1]; } }\n\
         var l = new L(); l.push(1, 2); l[5] = 9;\n\
         [Array.isArray(l), l.length, l.last(), l instanceof L, Array.isArray(L.from([1]))].join(' ');";
    assert_eq!(eval(source), "true 6 9 true true");
}
