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

/// A regex literal that starts with `=` in an argument or element list
/// (`s.replace(/=/g, "")`, js-base64's _mkUriSafe; highlight.js's
/// `[/const|var|let/, ..., /=\s*/, ...]`): the comma splitter read `/=` as
/// division assignment, so the list was split inside the literal and the
/// program failed. `/=` after an operand, and at the start of a line after
/// one, is still division assignment.
#[test]
fn regex_literals_starting_with_equals_in_lists() {
    check(
        "var out = ['a=b='.replace(/=/g, ''), 'a=b'.split(/=/, 1).length, \
         [/=/.source, /=a/g.flags].join(), \
         ((s) => s.replace(/=/g, '').replace(/[+/]/g, (m) => m == '+' ? '-' : '_'))('a+b/c=='), \
         [/=+/, /(a)?/].length];\n\
         var x = 6; x /= 2; var y = [8]; y[0] /=2;\n\
         out.push(x + y[0]);\n\
         out.join(' ')",
        "ab 1 =,g a-b_c 2 7",
    );
}

/// The symbol methods ToString their argument, so an object's toString runs
/// (it read "[object Object]"; Test262 RegExp/prototype/Symbol.split/
/// coerce-string and relatives) and a Symbol is a TypeError.
#[test]
fn symbol_methods_to_string_their_argument() {
    check(
        "var o = { toString() { return 'a-b'; } }; var r; \
         try { /x/[Symbol.split](Symbol()); r = 'none'; } catch (e) { r = e.constructor.name; } \
         [/-/[Symbol.split](o).join('|'), /b/[Symbol.search](o), /a/[Symbol.replace](o, 'X'), \
         /./g[Symbol.match](o).length, [..././g[Symbol.matchAll](o)].length, r].join(' ')",
        "a|b 2 X-b 3 3 TypeError",
    );
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

/// A regex literal leading a member chain followed by a top-level binary
/// operator: the operator binds looser than the chain. The parser took the
/// whole text as one postfix chain, so a trailing `[...]`
/// (`(/at .../i.exec(err.stack) || [])[1]`, Prism's currentScript lookup)
/// made `/ab/.source ||` a computed member's object.
#[test]
fn regex_member_chain_before_a_binary_operator() {
    check(
        "[(/ab/.exec('ab') || [])[0], (/ab/.source || []), /a/.source + [1], \
         (/x/.exec('y') || ['none'])[0], /a/.flags + /b/g.flags, \
         (/at [^(]*\\((.*)\\)$/i.exec('at f (x.js)') || [])[1]].join(' ')",
        "ab ab a1 none g x.js",
    );
}

/// bd-9vouw.275: String.prototype replace, replaceAll, split, match,
/// matchAll and search take the pattern's own @@replace/@@split/@@match/
/// @@search method first and call it with `this` itself, and convert `this`
/// with ToString only afterwards (replaceAll/matchAll's flags TypeError
/// comes before the conversion). An object `this` was converted first.
/// Expected lines are Node v22.2.0's output, captured programmatically; Bun
/// 1.4.2 agrees except for its console array formatting.
#[test]
fn string_pattern_methods_convert_this_after_the_pattern_bd_9vouw_275() {
    let source = r#"function kind(f) { try { return String(f()); } catch (e) { return e.constructor.name + (typeof e === 'object' ? '' : ':primitive'); } }
var log = [];
var poison = { toString: function () { log.push('this.toString'); throw new RangeError('poison'); } };
var noG = /./;
console.log(kind(function () { return ''.replaceAll.call(poison, noG, 'x'); }), kind(function () { return ''.matchAll.call(poison, noG); }), log.join());
log = [];
var custom = {};
custom[Symbol.replace] = function (s, r) { log.push('replace:' + (s === obj)); return 'R'; };
custom[Symbol.split] = function (s) { log.push('split:' + (s === obj)); return ['S']; };
custom[Symbol.match] = function (s) { log.push('match:' + (s === obj)); return 'M'; };
custom[Symbol.search] = function (s) { log.push('search:' + (s === obj)); return 7; };
var obj = { toString: function () { log.push('obj.toString'); return 'abc'; } };
console.log(''.replace.call(obj, custom, 'x'), ''.split.call(obj, custom), ''.match.call(obj, custom), ''.search.call(obj, custom), log.join());
log = [];
console.log(''.replace.call(obj, 'b', 'X'), ''.split.call(obj, 'b').join('|'), ''.replaceAll.call(obj, 'b', 'Y'), ''.search.call(obj, 'c'), log.join());
console.log(kind(function () { return ''.replace.call(undefined, custom, 'x'); }), kind(function () { return ''.split.call(null, custom); }), kind(function () { return ''.match.call({ toString: function () { return Symbol(); } }, 'a'); }));
console.log('a-b-c'.replaceAll('-', '+'), 'x1y2'.replace(/\d/g, '#'), 'a,b'.split(','), JSON.stringify('aXbX'.match(/X/g)), 'hello'.search('l'));
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
            "TypeError TypeError ",
            "R [ 'S' ] M 7 replace:true,split:true,match:true,search:true",
            "aXc a|c aYc 2 obj.toString,obj.toString,obj.toString,obj.toString",
            "TypeError TypeError TypeError",
            "a+b+c x#y# [ 'a', 'b' ] [\"X\",\"X\"] 2",
        ]
    );
}

/// bd-9vouw.283: IsRegExp asks @@match first: includes, startsWith and
/// endsWith reject a RegExp search string (or any object whose @@match is
/// truthy, while a RegExp with a false one is searched as text), a throwing
/// @@match getter propagates, and replaceAll / matchAll check the flags of
/// any object IsRegExp accepts. Expected lines: Node v22.2.0's output,
/// captured programmatically (Bun 1.4.2 agrees).
#[test]
fn string_methods_ask_is_regexp_bd_9vouw_283() {
    let source = r#"function k(f) { try { return String(f()); } catch (e) { return e.constructor.name; } }
var re = /a/;
console.log(k(function () { return 'abc'.startsWith(re); }), k(function () { return 'abc'.endsWith(re); }), k(function () { return 'abc'.includes(re); }));
var notRe = /a/; notRe[Symbol.match] = false;
console.log(k(function () { return '/a/'.startsWith(notRe); }), k(function () { return 'x/a/'.endsWith(notRe); }), k(function () { return 'x/a/x'.includes(notRe); }));
var fake = { toString: function () { return 'b'; } }; fake[Symbol.match] = true;
console.log(k(function () { return 'abc'.includes(fake); }), k(function () { return 'abc'.includes({ toString: function () { return 'b'; } }); }));
var poisoned = {}; Object.defineProperty(poisoned, Symbol.match, { get: function () { throw new RangeError(); } });
console.log(k(function () { return 'abc'.startsWith(poisoned); }), k(function () { return 'abc'.endsWith(poisoned); }), k(function () { return 'abc'.includes(poisoned); }));
var fakeFlags = { flags: '', toString: function () { return 'a'; } }; fakeFlags[Symbol.match] = true;
var fakeGlobal = { flags: 'g', toString: function () { return 'a'; } }; fakeGlobal[Symbol.match] = true;
console.log(k(function () { return 'aa'.replaceAll(fakeFlags, 'b'); }), k(function () { return 'aa'.replaceAll(fakeGlobal, 'b'); }), k(function () { return 'aa'.matchAll(fakeFlags).next().value; }), k(function () { return 'aa'.replaceAll(poisoned, 'b'); }));
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
            "TypeError TypeError TypeError",
            "true true true",
            "TypeError true",
            "RangeError RangeError RangeError",
            "TypeError bb TypeError RangeError",
        ]
    );
}
