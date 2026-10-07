#![forbid(unsafe_code)]

//! ES2020 21.2.3.1 RegExp(pattern, flags): IsRegExp (pattern[@@match]) runs
//! once; a called RegExp returns a pattern that IsRegExp, whose
//! `constructor` is RegExp, when no flags are given; an object IsRegExp
//! accepts that is not a RegExp supplies its `source` and `flags`; and
//! ToString converts the pattern and flags through ToPrimitive, pattern
//! first. The engine read every non-RegExp object as "[object Object]" and
//! always made a new RegExp (about 17 Node-passing Test262 tests in the
//! rc-next33 merged-tree census: S15.10.3.1_A1_*, S15.10.4.1_A8_*,
//! from-regexp-like*, call_with_non_regexp_same_constructor).

use frankenengine_engine::HybridRouter;

/// Calls and constructions with a RegExp, a regexp-like object (with and
/// without a RegExp `constructor`), conversion order and abrupt
/// conversions, an abrupt @@match getter, invalid flags and patterns, and
/// undefined / null / number patterns. Expected lines are Node v22.2.0's
/// output, captured programmatically.
#[test]
fn regexp_constructor_follows_is_regexp_and_to_string() {
    let source = r#"function k(f) { try { f(); return 'ok'; } catch (e) { return e.constructor.name + (e.message === 'boom' ? ':boom' : ''); } }
var re = /x/i;
console.log(RegExp(re) === re, RegExp(re, 'g') === re, new RegExp(re) === re, RegExp(re).flags, new RegExp(re, 'g').flags, new RegExp(re).source);
var like = { source: 'ab+', flags: 'g' };
like[Symbol.match] = true;
var copied = new RegExp(like);
console.log(copied.source, copied.flags, copied.test('xabbb'), RegExp(like) === like, new RegExp(like, 'i').flags);
like.constructor = RegExp;
console.log(RegExp(like) === like, new RegExp(like) === like);
var order = [];
var pattern = { toString: function () { order.push('pattern'); return 'p+'; } };
var flags = { toString: function () { order.push('flags'); return 'm'; } };
var made = new RegExp(pattern, flags);
console.log(made.source, made.flags, order.join(','));
console.log(new RegExp({ toString: void 0, valueOf: function () { return '[z-z]'; } }, { toString: void 0, valueOf: function () { return 'mig'; } }).flags);
console.log(k(function () { new RegExp({ toString: function () { throw new Error('boom'); } }); }), k(function () { new RegExp('a', { toString: function () { throw new Error('boom'); } }); }), k(function () { new RegExp('a', 'gg'); }), k(function () { RegExp('(', ''); }));
var getter = /y/;
Object.defineProperty(getter, Symbol.match, { get: function () { throw new Error('boom'); } });
console.log(k(function () { new RegExp(getter); }), String(new RegExp(undefined)), String(new RegExp(null)), String(RegExp(12, undefined)));
"#;
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
            "true false false i g x",
            "ab+ g true false i",
            "true false",
            "p+ m pattern,flags",
            "gim",
            "Error:boom Error:boom SyntaxError SyntaxError",
            "Error:boom /(?:)/ /null/ /12/",
        ]
    );
}
