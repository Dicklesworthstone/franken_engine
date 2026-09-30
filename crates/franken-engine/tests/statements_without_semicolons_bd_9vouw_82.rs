//! Statements separated only by line breaks inside braces (bd-9vouw.82).
//!
//! Code without semicolons (StandardJS, Prettier `semi: false`) only parsed at
//! top level: the logical-line merger joined the physical lines of a block,
//! function, callback, class or object body with spaces, so
//! `function f() {\n  let a = 1\n  let b = 2\n}` became `let a = 1 let b = 2`
//! and failed with "unseparated expression sequence". A line break whose
//! innermost enclosing bracket is `{` now survives the merge, and the body's
//! own merge applies the usual line rules. Line breaks inside parentheses and
//! brackets still join (call arguments, array literals). `return` and `yield`
//! end at a line break (restricted productions). Expected values are Node
//! v22.2.0's completion values for the same programs (`vm.runInThisContext`).

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
fn function_body_declarations() {
    check(
        r#"function f() {
  let a = 1
  let b = 2
  return a + b
}
f()"#,
        "3",
    );
}

#[test]
fn function_body_assignments() {
    check(
        r#"function f() {
  let a = 1
  a = a + 1
  a += 2
  a *= 3
  return a
}
f()"#,
        "12",
    );
}

#[test]
fn function_body_member_stores() {
    check(
        r#"function f() {
  const o = { x: 1 }
  o.y = 2
  o['z'] = 3
  return o.x + o.y + o.z
}
f()"#,
        "6",
    );
}

#[test]
fn function_body_calls_and_updates() {
    check(
        r#"function g() { return 5 }
function f() {
  let t = 0
  t += g()
  g()
  t++
  return t
}
f()"#,
        "6",
    );
}

#[test]
fn callback_in_call_arguments() {
    check(
        r#"let total = 0
let count = 0
;[1, 2, 3].forEach(x => {
  total += x
  count++
})
total + ':' + count"#,
        "6:3",
    );
}

#[test]
fn function_expression_callback() {
    check(
        r#"[1, 2].map(function (x) {
  const y = x * 2
  return y + 1
}).join()"#,
        "3,5",
    );
}

#[test]
fn object_literal_in_body() {
    check(
        r#"function f() {
  const cfg = {
    port: 80,
    host: 'h'
  }
  return cfg.host + cfg.port
}
f()"#,
        "h80",
    );
}

#[test]
fn destructuring_across_lines() {
    check(
        r#"function f() {
  const {
    a,
    b
  } = { a: 1, b: 2 }
  const [
    x,
    y
  ] = [3, 4]
  return a + b + x + y
}
f()"#,
        "10",
    );
}

#[test]
fn class_fields_on_their_own_lines() {
    check(
        r#"class A {
  state = { n: 1 }
  handle = () => this.state.n + 1
  static tag = 'A'
  get double () { return this.state.n * 2 }
  m () {
    const v = this.handle()
    return v * 10
  }
}
const a = new A();
[a.state.n, a.handle(), A.tag, a.double, a.m()].join(' ')"#,
        "1 2 A 2 20",
    );
}

#[test]
fn class_fields_without_initializers() {
    check(
        r#"class B {
  x = 1
  y = this.x + 1
  z
  w
}
const b = new B();
[b.x, b.y, b.z, 'w' in b].join(' ')"#,
        "1 2  true",
    );
}

#[test]
fn switch_cases() {
    check(
        r#"function f() {
  let r = ''
  for (const v of [1, 2, 3]) {
    switch (v) {
      case 1:
        r += 'a'
        break
      case 2:
        r += 'b'
        r += 'B'
        break
      default:
        r += 'c'
    }
  }
  return r
}
f()"#,
        "abBc",
    );
}

#[test]
fn allman_if_else() {
    check(
        r#"function f() {
  let r
  if (2 > 1)
  {
    r = 'big'
  }
  else
  {
    r = 'small'
  }
  return r
}
f()"#,
        "big",
    );
}

#[test]
fn try_catch_finally() {
    check(
        r#"function f() {
  let log = []
  try {
    log.push(1)
    throw new Error('x')
  } catch (e) {
    log.push(e.message)
  } finally {
    log.push(2)
  }
  return log.join()
}
f()"#,
        "1,x,2",
    );
}

#[test]
fn do_while() {
    check(
        r#"function f() {
  let i = 0
  do {
    i++
  } while (i < 3)
  return i
}
f()"#,
        "3",
    );
}

#[test]
fn method_chain() {
    check(
        r#"function f() {
  const r = [3, 1, 2]
    .map(x => x * 2)
    .filter(x => x > 2)
    .join('-')
  return r
}
f()"#,
        "6-4",
    );
}

#[test]
fn ternary_across_lines() {
    check(
        r#"function f() {
  const v = 5 > 1
    ? 'yes'
    : 'no'
  return v
}
f()"#,
        "yes",
    );
}

#[test]
fn nested_functions() {
    check(
        r#"function f() {
  function inner (a) {
    const b = a * 2
    return b
  }
  const c = inner(3)
  return c + 1
}
f()"#,
        "7",
    );
}

#[test]
fn loop_bodies() {
    check(
        r#"function f() {
  let s = 0
  for (let i = 0; i < 3; i++) {
    s += i
    s *= 2
  }
  let n = 3
  while (n > 0) {
    s += n
    n--
  }
  return s
}
f()"#,
        "14",
    );
}

#[test]
fn labeled_continue() {
    check(
        r#"function f() {
  let r = 0
  outer:
  for (const a of [1, 2]) {
    for (const b of [1, 2]) {
      if (b === 2) continue outer
      r += a * b
    }
  }
  return r
}
f()"#,
        "3",
    );
}

#[test]
fn accessors() {
    check(
        r#"const o = {
  _v: 1,
  get v () {
    const t = this._v
    return t * 10
  },
  set v (x) {
    const t = x
    this._v = t
  }
}
o.v = 4
o.v"#,
        "40",
    );
}

#[test]
fn comments_between_statements() {
    check(
        r#"function f() {
  // first
  let a = 1 // trailing
  /* block
     comment */
  let b = 2
  return a + b
}
f()"#,
        "3",
    );
}

#[test]
fn template_across_lines() {
    check(
        r#"function f() {
  const name = 'n'
  const s = `a ${name}
b`
  return s.length
}
f()"#,
        "5",
    );
}

#[test]
fn regex_in_body() {
    check(
        r#"function f(s) {
  const re = /a+/g
  const m = s.match(re)
  return m.length
}
f('aa b aaa')"#,
        "2",
    );
}

#[test]
fn leading_semicolon_iife() {
    check(
        r#"let out = 0
;(function () {
  out = 7
  out++
})()
out"#,
        "8",
    );
}

#[test]
fn call_arguments_across_lines() {
    check(
        r#"function add (a, b, c) { return a + b + c }
add(
  1,
  2,
  3
)"#,
        "6",
    );
}

#[test]
fn array_and_object_arguments_across_lines() {
    check(
        r#"function show (o, a) { return o.a + o.b + a.length }
show({
  a: 1,
  b: 2
}, [
  1,
  2
])"#,
        "5",
    );
}

#[test]
fn method_in_object_argument() {
    check(
        r#"function run (o) { return o.go() }
run({
  go () {
    const x = 2
    const y = 3
    return x * y
  }
})"#,
        "6",
    );
}

#[test]
fn return_ends_at_a_line_break() {
    check(
        r#"function f() {
  let a = 1
  return
  a + 1
}
String(f())"#,
        "undefined",
    );
}

#[test]
fn yield_ends_at_a_line_break() {
    check(
        r#"function* g() {
  yield
  1
  yield 2
}
[...g()].map(String).join()"#,
        "undefined,2",
    );
}

#[test]
fn update_operators_end_a_line() {
    check(
        r#"let i = 0
i++
i--
i++
function f() {
  let t = 0
  t++
  t++
  t--
  return t
}
[i, f()].join()"#,
        "1,1",
    );
}

#[test]
fn binary_plus_after_update_continues() {
    check(
        r#"let a = 1
let b = a+++
2
let c = a++ +
3
String([a, b, c])"#,
        "3,3,5",
    );
}

#[test]
fn ieee754_read() {
    check(
        r#"/*! ieee754. BSD-3-Clause License. Feross Aboukhadijeh <https://feross.org/opensource> */
function read (buffer, offset, isLE, mLen, nBytes) {
  var e, m
  var eLen = (nBytes * 8) - mLen - 1
  var eMax = (1 << eLen) - 1
  var eBias = eMax >> 1
  var nBits = -7
  var i = isLE ? (nBytes - 1) : 0
  var d = isLE ? -1 : 1
  var s = buffer[offset + i]

  i += d

  e = s & ((1 << (-nBits)) - 1)
  s >>= (-nBits)
  nBits += eLen
  for (; nBits > 0; e = (e * 256) + buffer[offset + i], i += d, nBits -= 8) {}

  m = e & ((1 << (-nBits)) - 1)
  e >>= (-nBits)
  nBits += mLen
  for (; nBits > 0; m = (m * 256) + buffer[offset + i], i += d, nBits -= 8) {}

  if (e === 0) {
    e = 1 - eBias
  } else if (e === eMax) {
    return m ? NaN : ((s ? -1 : 1) * Infinity)
  } else {
    m = m + Math.pow(2, mLen)
    e = e - eBias
  }
  return (s ? -1 : 1) * m * Math.pow(2, e - mLen)
}
read([0x40, 0x49, 0x0f, 0xdb], 0, false, 23, 4)"#,
        "3.1415927410125732",
    );
}

#[test]
fn declaration_keyword_before_a_line_comment_continues() {
    // `var` with its first binding on the next line, after a comment:
    // moment 2.29.4's firstWeekOffset. Line breaks reach function bodies since
    // this change, and a line ending in `var` ended the statement there
    // ("var declaration must include at least one binding"). A declaration
    // keyword with no binding cannot end a statement; the same word as a
    // property name (`cfg.const`) can.
    check("var // c\n  a = 1;\na;", "1");
    check("let // c\n  b = 2;\nb;", "2");
    check("const // c\n  k = 3;\nk;", "3");
    check(
        "function f(dow, doy) {\n  var // first-week day\n    fwd = 7 + dow - doy,\n    \
         // first-week day local weekday\n    fwdlw = (7 + fwd - dow) % 7;\n  \
         return -fwdlw + fwd - 1;\n}\nf(1, 4);",
        "0",
    );
    check("var cfg = { const: 4 };\nvar v = cfg.const\nv;", "4");
}
