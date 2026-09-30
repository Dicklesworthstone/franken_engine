//! RegExp.prototype[@@match], [@@matchAll], [@@replace], [@@search] and
//! [@@split] (ES2020 21.2.5.6-11), and the String methods that defer to a
//! pattern object's symbol method (21.1.3.11/.12/.17/.18/.19 step 2).
//!
//! Before this change the five methods were undefined
//! (`typeof RegExp.prototype[Symbol.split]` was "undefined"), and
//! `'x-y'.split(obj)` ignored an object's own `[Symbol.split]` and split on
//! its string form. Expected strings are Node v22.2.0's completion values
//! for the same programs.
//!
//! No-claim: on a RegExp the methods run the engine's RegExp algorithm; a
//! user-overridden `exec`, a RegExp subclass's species constructor and the
//! generic (non-RegExp receiver) forms of the spec algorithms are not
//! consulted, and a non-RegExp receiver is a TypeError.
//!
//! No mocks: real source through the public `HybridRouter::eval` path.

use frankenengine_engine::HybridRouter;

fn check(source: &str, node: &str) {
    let value = match HybridRouter::default().eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERROR: {err:?}"),
    };
    assert_eq!(value, node, "`{source}` must match Node v22.2.0");
}

#[test]
fn regexp_prototype_has_the_five_symbol_methods() {
    check(
        "[typeof RegExp.prototype[Symbol.match], typeof RegExp.prototype[Symbol.matchAll], \
         typeof RegExp.prototype[Symbol.replace], typeof RegExp.prototype[Symbol.search], \
         typeof RegExp.prototype[Symbol.split]].join()",
        "function,function,function,function,function",
    );
    check(
        "[RegExp.prototype[Symbol.split].name, RegExp.prototype[Symbol.replace].length, \
         RegExp.prototype[Symbol.matchAll].name, RegExp.prototype[Symbol.search].length].join()",
        "[Symbol.split],2,[Symbol.matchAll],1",
    );
}

#[test]
fn symbol_methods_run_the_regexp_algorithms() {
    check(
        "[/b/[Symbol.match]('abc')[0], /b/g[Symbol.replace]('abcb', 'X'), \
         /c/[Symbol.search]('abc'), /,/[Symbol.split]('a,b,c', 2).join('|')].join(' ')",
        "b aXcX 2 a|b",
    );
    check(
        "[...'aXbX'.matchAll(/x/gi)].map((m) => m.index).join() + ' ' + \
         [.../a/g[Symbol.matchAll]('aba')].length",
        "1,3 2",
    );
    check(
        "RegExp.prototype[Symbol.split].call(/-/, 'a-b').join() + ' ' + \
         RegExp.prototype[Symbol.replace].call(/a/g, 'aba', 'c')",
        "a,b cbc",
    );
    // The ordinary RegExp forms keep their results.
    check(
        "'a,b'.split(/,/).join('|') + ' ' + 'x1y2'.replace(/\\d/g, (d) => '<' + d + '>') + ' ' + \
         'abc'.search(/c/) + ' ' + 'aaa'.match(/a/g).length",
        "a|b x<1>y<2> 2 3",
    );
}

#[test]
fn string_methods_defer_to_a_pattern_objects_symbol_method() {
    check(
        "const o = { [Symbol.split](s, lim) { return ['custom', s, lim]; } }; 'x-y'.split(o, 3).join()",
        "custom,x-y,3",
    );
    check(
        "const r = { [Symbol.replace](s, rep) { return s + '!' + rep; } }; \
         'abc'.replace(r, 'Z') + ' ' + 'abc'.replaceAll(r, 'W')",
        "abc!Z abc!W",
    );
    check(
        "const m = { [Symbol.match](s) { return ['M' + s]; } }; 'q'.match(m)[0]",
        "Mq",
    );
    check(
        "const se = { [Symbol.search](s) { return 42; } }; 'q'.search(se)",
        "42",
    );
    check(
        "const ma = { [Symbol.matchAll](s) { return 'all:' + s; } }; 'q'.matchAll(ma)",
        "all:q",
    );
    // A RegExp's own symbol method wins over the prototype's.
    check(
        "const re = /,/; re[Symbol.split] = function (s) { return ['own', s]; }; 'a,b'.split(re).join()",
        "own,a,b",
    );
    // A non-callable symbol method is a TypeError.
    check(
        "let r; try { 'x'.split({ [Symbol.split]: 5 }); } catch (e) { r = e.constructor.name; } r",
        "TypeError",
    );
}
