#![forbid(unsafe_code)]

//! bd-9vouw.184: Function.prototype.toString returns a user function's
//! source text (ES2024 20.2.3.5): the text its definition matched, comments
//! and layout included. It returned `function name() { [native code] }` for
//! every function, so source-map-js (shipped by postcss, terser and most
//! bundlers), which clones its quick-sort with
//! `new Function('return ' + SortTemplate.toString())()`, aborted the run on
//! the Function constructor's parse error, and native-function detection
//! (lodash's isNative) took every user function for a built-in.
//!
//! PROGRAM covers declarations with comments in the head and body,
//! function expressions, arrows (expression and block bodies, async),
//! generators and async functions, a class and its constructor, static,
//! accessor, generator, async and computed methods (a method's text starts
//! after `static`, as in Node), a class expression with heritage, object
//! literal methods, accessors and function-valued properties, a nested
//! function whose body spans lines, built-ins and bound functions (the
//! NativeFunction form), and the source-map-js clone. Expected lines are
//! Node v22.2.0's output, captured programmatically.
//!
//! No-claim: functions the Function constructor builds answer the text of
//! the engine's synthesized source; a function whose parse text the parser
//! re-assembled (rather than sliced) answers the NativeFunction form.

use frankenengine_engine::HybridRouter;

#[test]
fn user_functions_answer_their_source_text_bd_9vouw_184() {
    let source = r##"function /* a */ declared /* b */ (x, /* c */ y) /* d */ {
  // body comment
  return x + y; /* tail */
}
console.log(JSON.stringify(declared.toString()));
var expr = function named(a) { return a * 2; };
var anon = function (a, b) {
  return a - b;
};
console.log(JSON.stringify(String(expr)), JSON.stringify(String(anon)));
var arrow1 = (a, b) => a + b;
var arrow2 = x => { return x; };
var arrow3 = async (q) => await q;
console.log(JSON.stringify(String(arrow1)), JSON.stringify(String(arrow2)), JSON.stringify(String(arrow3)));
function* gen() { yield 1; }
async function asyncFn() { await null; }
async function* asyncGen() {}
console.log(JSON.stringify(String(gen)), JSON.stringify(String(asyncFn)), JSON.stringify(String(asyncGen)));
class Shape /* heritage-free */ {
  constructor(w) { this.w = w; }
  static create() { return new Shape(1); }
  get area() { return this.w * this.w; }
  set area(v) { this.w = Math.sqrt(v); }
  *items() { yield this.w; }
  async load() {}
  ['comp' + 'uted'](z) { return z; }
}
console.log(JSON.stringify(String(Shape)));
var desc = Object.getOwnPropertyDescriptor(Shape.prototype, 'area');
console.log(JSON.stringify(String(Shape.create)), JSON.stringify(String(desc.get)), JSON.stringify(String(desc.set)));
console.log(JSON.stringify(String(Shape.prototype.items)), JSON.stringify(String(Shape.prototype.load)), JSON.stringify(String(Shape.prototype.computed)));
var Expr = class Named extends Shape { method() { return super.area; } };
console.log(JSON.stringify(String(Expr)), JSON.stringify(String(Expr.prototype.method)));
var obj = {
  plain(a) { return a; },
  get prop() { return 1; },
  set prop(v) {},
  async am() {},
  *gm() {},
  arrowProp: (k) => k,
  fnProp: function (k) { return k; },
};
var od = Object.getOwnPropertyDescriptor(obj, 'prop');
console.log(JSON.stringify(String(obj.plain)), JSON.stringify(String(od.get)), JSON.stringify(String(od.set)));
console.log(JSON.stringify(String(obj.am)), JSON.stringify(String(obj.gm)), JSON.stringify(String(obj.arrowProp)), JSON.stringify(String(obj.fnProp)));
function outer() {
  function inner(n) {
    return n
      + 1;
  }
  return inner;
}
console.log(JSON.stringify(String(outer())));
console.log(String(Math.max), String(function () {}.bind(null)), String(class {}), String(() => {}));
function SortTemplate(comparator) {
  function swap(ary, x, y) { var t = ary[x]; ary[x] = ary[y]; ary[y] = t; }
  return function (ary) { swap(ary, 0, 1); return comparator(ary[0], ary[1]); };
}
var clone = new Function('return ' + SortTemplate.toString())();
console.log(typeof clone, clone.name, clone(function (a, b) { return a - b; })([2, 1]));
console.log(/\[native code\]/.test(Function.prototype.toString.call(declared)), /\[native code\]/.test(Function.prototype.toString.call(Array.prototype.push)));"##;
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
            r##""function /* a */ declared /* b */ (x, /* c */ y) /* d */ {\n  // body comment\n  return x + y; /* tail */\n}""##,
            r##""function named(a) { return a * 2; }" "function (a, b) {\n  return a - b;\n}""##,
            r##""(a, b) => a + b" "x => { return x; }" "async (q) => await q""##,
            r##""function* gen() { yield 1; }" "async function asyncFn() { await null; }" "async function* asyncGen() {}""##,
            r##""class Shape /* heritage-free */ {\n  constructor(w) { this.w = w; }\n  static create() { return new Shape(1); }\n  get area() { return this.w * this.w; }\n  set area(v) { this.w = Math.sqrt(v); }\n  *items() { yield this.w; }\n  async load() {}\n  ['comp' + 'uted'](z) { return z; }\n}""##,
            r##""create() { return new Shape(1); }" "get area() { return this.w * this.w; }" "set area(v) { this.w = Math.sqrt(v); }""##,
            r##""*items() { yield this.w; }" "async load() {}" "['comp' + 'uted'](z) { return z; }""##,
            r##""class Named extends Shape { method() { return super.area; } }" "method() { return super.area; }""##,
            r##""plain(a) { return a; }" "get prop() { return 1; }" "set prop(v) {}""##,
            r##""async am() {}" "*gm() {}" "(k) => k" "function (k) { return k; }""##,
            r##""function inner(n) {\n    return n\n      + 1;\n  }""##,
            r##"function max() { [native code] } function () { [native code] } class {} () => {}"##,
            r##"function SortTemplate -1"##,
            r##"false true"##,
        ]
    );
}
