#![forbid(unsafe_code)]

//! bd-9vouw.208: `get RegExp.prototype.flags` is generic (ES2020 21.2.5.4):
//! any object answers through its boolean flag properties, read in the
//! order hasIndices, global, ignoreCase, multiline, dotAll, unicode,
//! unicodeSets, sticky; a non-object is a TypeError. The getter demanded a
//! RegExp receiver, so the regexp.prototype.flags polyfill's feature test
//! (a plain object with `hasIndices` and `sticky` getters, expecting "dy")
//! threw, and deep-equal failed to load.
//!
//! Expected lines are Node v22.2.0's output (Bun 1.4.2 prints the same).

use frankenengine_engine::HybridRouter;

#[test]
fn regexp_flags_getter_reads_any_object() {
    let source = "var get = Object.getOwnPropertyDescriptor(RegExp.prototype, 'flags').get;\nvar s = '';\nvar o = {};\nObject.defineProperty(o, 'hasIndices', { get: function () { s += 'd'; return false; } });\nObject.defineProperty(o, 'sticky', { get: function () { s += 'y'; return true; } });\nvar r = get.call(o);\nconsole.log(JSON.stringify(r), s, get.call({ global: 1, multiline: 'x', dotAll: 0 }), get.call(/a/gimsuy));\ntry { get.call(1); } catch (e) { console.log(e.name); }\n";
    let lines: Vec<String> = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .console_output
        .into_iter()
        .map(|entry| entry.message)
        .collect();
    assert_eq!(lines, ["\"y\" dy gm gimsuy", "TypeError"]);
}

/// bd-9vouw.213: RegExp.prototype.exec and test convert their argument with
/// ToString (ES2020 21.2.5.2.1, 21.2.5.13), which runs an object's
/// @@toPrimitive, toString or valueOf; a missing argument is "undefined" and
/// a Symbol is a TypeError. `lastIndex` is writable, non-enumerable and
/// non-configurable. is-regex (under deep-equal's safe-regex-test) tells a
/// RegExp by both: an own data `lastIndex`, and an exec whose argument's
/// toString throws a marker; exec read the object as "[object Object]" and
/// returned, so a RegExp was "not a RegExp".
#[test]
fn regexp_exec_and_test_convert_their_argument_bd_9vouw_213() {
    let source = "var marker = {};\nvar bad = { toString: function () { throw marker; }, valueOf: function () { throw marker; } };\nbad[Symbol.toPrimitive] = function () { throw marker; };\nfunction thrown(f) { try { f(); return 'none'; } catch (e) { return e === marker ? 'marker' : e.name; } }\nvar exec = Function.prototype.call.bind(RegExp.prototype.exec);\nvar d = Object.getOwnPropertyDescriptor(/a/g, 'lastIndex');\nconsole.log(d.writable, d.enumerable, d.configurable);\nconsole.log(thrown(function () { /a/.exec(bad); }), thrown(function () { /a/.test(bad); }), thrown(function () { exec(/a/, bad); }), thrown(function () { RegExp.prototype.exec.call({}, bad); }));\nvar s = { toString: function () { return 'xa'; } };\nvar p = {}; p[Symbol.toPrimitive] = function (hint) { return hint + 'a'; };\nconsole.log(/a/.exec(s)[0], /a/.test(s), /stringa/.test(p), /undefined/.test(), /u/.exec()[0], thrown(function () { /a/.test(Symbol()); }));\n";
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
            "true false false",
            "marker marker marker TypeError",
            "a true true true u TypeError"
        ]
    );
}

/// bd-9vouw.243: a RegExp's `source` is its pattern escaped as a literal
/// body (ES2020 21.2.3.2.4 EscapeRegExpPattern): `(?:)` for an empty
/// pattern, `\/` for a `/` outside a class, escape sequences for line
/// terminators. `new RegExp('a/b').source` was `a/b`, so
/// `String(new RegExp('a/b'))` was the unparsable `/a/b/`. The escaped
/// pattern still matches what the original did. Expected lines are Node
/// v22.2.0's output, captured programmatically.
#[test]
fn regexp_source_is_escaped_like_a_literal_body_bd_9vouw_243() {
    let source = r#"var cases = ['', 'a/b', 'a\\/b', '[/]', '[a/]b/c', '\n', 'a\r\u2028\u2029b', '\\\n', '[\n]', '/', 'a\\\\/b', '(?:)', '[\\]/]/'];
console.log(cases.map(function (c) { return JSON.stringify(new RegExp(c).source); }).join(' '));
console.log(cases.map(function (c) { var r = new RegExp(c); return String(new RegExp(r.source).source === r.source); }).join(' '));
console.log(String(new RegExp('a/b')), String(new RegExp('')), JSON.stringify(String(new RegExp('x\ny', 'g'))), /a\/b/.source, /[/]/.source);
console.log(new RegExp('a/b').test('xa/b'), new RegExp('\n').test('\n'), new RegExp('[\n]').test('\n'), new RegExp('\\\n').test('\n'), new RegExp('').test('q'), new RegExp('a/b').exec('a/b')[0]);
var re = /x/g;
re.compile('p/q', 'i');
console.log(re.source, String(re), re.test('P/Q'));"#;
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
            r#""(?:)" "a\\/b" "a\\/b" "[/]" "[a/]b\\/c" "\\n" "a\\r\\u2028\\u2029b" "\\n" "[\\n]" "\\/" "a\\\\\\/b" "(?:)" "[\\]/]\\/""#,
            r#"true true true true true true true true true true true true true"#,
            r#"/a\/b/ /(?:)/ "/x\\ny/g" a\/b [/]"#,
            r#"true true true true true a/b"#,
            r#"p\/q /p\/q/i true"#,
        ]
    );
}

/// bd-9vouw.257 (first part): RegExp.prototype.test is RegExpExec(R, S)
/// (ES2020 21.2.5.13, 21.2.5.2.1). `this` must be an object; a callable
/// `exec` other than the intrinsic one runs instead of the matcher (its
/// result must be an object or null), so a subclass overriding exec or an
/// object borrowing test answers through it; an object with neither is a
/// TypeError (it answered false). RegExpBuiltinExec reads
/// ToLength(lastIndex) for every regexp, global or not, so an object
/// lastIndex's valueOf runs once (and may throw) and the property keeps the
/// object. Expected lines are Node v22.2.0's output, captured
/// programmatically.
///
/// The symbol methods are covered by
/// regexp_symbol_methods_run_regexp_exec_bd_9vouw_257 below.
#[test]
fn regexp_test_runs_regexp_exec_bd_9vouw_257() {
    let source = r#"function attempt(f) { try { return String(f()); } catch (e) { return e.constructor.name; } }
var o = { test: RegExp.prototype.test };
console.log(attempt(() => o.test('x')), attempt(() => RegExp.prototype.test.call(1, 'x')), attempt(() => RegExp.prototype.test.call(undefined, 'x')));
var calls = 0;
var withExec = { exec(s) { calls++; return s === 'hit' ? {} : null; } };
console.log(RegExp.prototype.test.call(withExec, 'hit'), RegExp.prototype.test.call(withExec, 'miss'), calls);
var r = /a/;
r.exec = function () { return null; };
console.log(r.test('a'), attempt(() => { var q = /a/; q.exec = () => 1; return q.test('a'); }), attempt(() => { var q = /a/; q.exec = 5; return q.test('a'); }));
class R extends RegExp { exec(s) { return s.length > 2 ? super.exec(s) : null; } }
console.log(new R('a').test('a'), new R('a').test('aaa'));
var gets = 0;
var counter = { valueOf() { gets++; return 1; } };
var g = /b/g;
g.lastIndex = counter;
var m = g.exec('bab');
console.log(m && m.index, g.lastIndex, gets);
var ng = /./;
ng.lastIndex = counter;
ng.exec('abc');
console.log(ng.lastIndex === counter, gets);
var thrower = /a/;
thrower.lastIndex = { valueOf() { throw new SyntaxError('li'); } };
console.log(attempt(() => thrower.exec('a')), attempt(() => thrower.test('a')));
var gt = /b/g;
gt.lastIndex = { valueOf() { return 2; } };
console.log(gt.test('abcb'), gt.lastIndex, /a/.test('a'), /a/g.test('ba'));"#;
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
            r#"TypeError TypeError TypeError"#,
            r#"true false 2"#,
            r#"false TypeError true"#,
            r#"false true"#,
            r#"2 3 1"#,
            r#"true 2"#,
            r#"SyntaxError SyntaxError"#,
            r#"true 4 true true"#,
        ]
    );
}

/// bd-9vouw.257 (second part): RegExp.prototype[@@match], [@@search],
/// [@@replace] and [@@split] run their ES2024 22.2.6 algorithms for any
/// receiver that is not a pristine RegExp: RegExpExec calls a user `exec`
/// (own, or a subclass method) and checks its result, the exec result's
/// `0`, `index`, `length`, captures and `groups` are read and coerced, a
/// global match or replace sets and steps `lastIndex` (a read-only one is
/// a TypeError), @@search restores `lastIndex`, @@split constructs its
/// splitter through @@species (with the limit coerced after), and a plain
/// object borrowing the methods works through its `exec`. The String
/// methods reach them through the pattern's builtin @@method. A pristine
/// RegExp keeps the matcher (last lines). Expected lines are Node v22.2.0's
/// output, captured programmatically.
///
/// No-claim: @@matchAll keeps the matcher path.
#[test]
fn regexp_symbol_methods_run_regexp_exec_bd_9vouw_257() {
    let source = r##"function attempt(f) { try { return String(f()); } catch (e) { return e.constructor.name; } }
var log = [];
var r = /a/g;
r.exec = function (s) { return this.lastIndex++ < 2 ? { 0: 'Q' + this.lastIndex, index: 0, length: 1 } : null; };
console.log(JSON.stringify('aaa'.match(r)), r.lastIndex);
var s1 = /b/;
s1.lastIndex = 7;
s1.exec = function () { this.lastIndex = 3; return { index: 42 }; };
console.log('abc'.search(s1), s1.lastIndex, 'abc'.search({ [Symbol.search]: RegExp.prototype[Symbol.search], exec() { return null; }, lastIndex: 0 }));
var rep = /x/;
rep.exec = function () { return { 0: 'bc', 1: 'C', 2: undefined, index: 1, length: 3, groups: { n: 'N' } }; };
console.log('abcd'.replace(rep, '[$&|$1|$2|$<n>|$`|$\'|$$|$3]'), 'abcd'.replace(rep, function () { return JSON.stringify([].slice.call(arguments)); }));
var many = 0;
var rg = /./g;
rg.exec = function (s) { return many++ < 3 ? { 0: '', index: many, length: 1 } : null; };
console.log('wxyz'.replace(rg, '-'), rg.lastIndex);
class Splitter extends RegExp {
  static get [Symbol.species]() { return Splitter; }
  exec(s) { var m = super.exec(s); log.push('sx' + this.lastIndex); return m; }
}
log = [];
console.log(JSON.stringify('a1b22c'.split(new Splitter('\\d+'))), log.length > 0, JSON.stringify('a,b,,c'.split(new Splitter(','), 2)));
var plain = { exec(s) { return s === 'hit' ? { 0: 'hit', index: 0, length: 1 } : null; }, flags: '' };
console.log(JSON.stringify(RegExp.prototype[Symbol.match].call(plain, 'hit')), RegExp.prototype[Symbol.replace].call(plain, 'hit', 'X'), attempt(() => RegExp.prototype[Symbol.match].call(1, 'a')), attempt(() => RegExp.prototype[Symbol.split].call({}, 'a')));
var throwing = /a/;
throwing.exec = function () { throw new RangeError('boom'); };
console.log(attempt(() => 'a'.match(throwing)), attempt(() => 'a'.replace(throwing, 'b')), attempt(() => 'a'.search(throwing)));
var badResult = /a/;
badResult.exec = function () { return 5; };
console.log(attempt(() => 'a'.match(badResult)), attempt(() => 'a'.split(badResult)));
var frozen = /a/g;
frozen.exec = function () { return null; };
Object.defineProperty(frozen, 'lastIndex', { writable: false, value: 0 });
console.log(attempt(() => 'a'.match(frozen)), attempt(() => 'a'.replace(frozen, 'b')));
console.log(JSON.stringify('a-b-c'.split(/-/)), 'a-b-c'.replace(/-/g, '+'), 'abc'.search(/c/), JSON.stringify('xAyA'.match(/A/g)), JSON.stringify('😀x😀'.split(/(?:)/u)));
var u = /(?:)/gu;
u.exec = function (s) { var m = RegExp.prototype.exec.call(this, s); return m; };
console.log(JSON.stringify('😀a'.match(u)), JSON.stringify('😀a'.replace(u, '|')));
var lim = { valueOf() { log.push('limit'); return 2; } };
log = [];
console.log(JSON.stringify('a,b,c'.split(new Splitter(','), lim)), log[0]);
var ci = /a/;
Object.defineProperty(ci, 'flags', { value: 'i' });
console.log(JSON.stringify('xAyaz'.split(ci)), JSON.stringify('xAyaz'.split(/a/)), JSON.stringify('xAyaz'.split(/a/i)));"##;
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
            r##"["Q1","Q2"] 3"##,
            r##"42 7 -1"##,
            r##"a[bc|C||N|a|d|$|$3]d a["bc","C",null,1,"abcd",{"n":"N"}]d"##,
            r##"w-x-y-z 3"##,
            r##"["a","b","c"] true ["a","b"]"##,
            r##"{"0":"hit","index":0,"length":1} X TypeError SyntaxError"##,
            r##"RangeError RangeError RangeError"##,
            r##"TypeError ,"##,
            r##"TypeError TypeError"##,
            r##"["a","b","c"] a+b+c 2 ["A","A"] ["😀","x","😀"]"##,
            r##"["","",""] "|😀|a|""##,
            r##"["a","b"] limit"##,
            r##"["x","y","z"] ["xAy","z"] ["x","y","z"]"##,
        ]
    );
}

/// bd-9vouw.257 (second part): @@match, @@replace and @@split read
/// ToString(Get(rx, "flags")) (ES2024 22.2.6.8 step 4, 22.2.6.11 step 6,
/// 22.2.6.14 step 4), so an own `flags` decides global and full-Unicode
/// matching, and String.prototype.replaceAll checks the observable flags
/// of a RegExp that is not pristine. Node v22.2.0 (V8 12.4) still reads
/// `global` and `unicode` there (ES2020 21.2.5.6 step 4) and fails
/// Test262's Symbol.match/get-flags-err.js and flags-tostring-error.js;
/// expected lines are Bun 1.4.2's (JavaScriptCore) output, captured
/// programmatically.
#[test]
fn regexp_symbol_methods_read_flags_bd_9vouw_257() {
    let source = r##"function attempt(f) { try { return String(f()); } catch (e) { return e.constructor.name; } }
var log = [];
var traced = {
  n: 0,
  get flags() { log.push('flags'); return 'g'; },
  get lastIndex() { log.push('get li'); return this._li || 0; },
  set lastIndex(v) { log.push('set li ' + v); this._li = v; },
  exec(s) { log.push('exec'); return this.n++ < 2 ? { 0: this.n === 2 ? '' : 'x', index: 0, length: 1 } : null; },
};
console.log(JSON.stringify(RegExp.prototype[Symbol.match].call(traced, 'abc')), log.join());
var sticky = /a/y;
Object.defineProperty(sticky, 'flags', { value: 'gy' });
console.log('aaXa'.replace(sticky, 'b'), 'aaXa'.replaceAll(sticky, 'b'), JSON.stringify('aaXa'.match(sticky)), JSON.stringify('aaXa'.match(/a/y)));
var nonGlobal = /a/g;
Object.defineProperty(nonGlobal, 'flags', { value: '' });
console.log(attempt(() => 'aa'.replaceAll(nonGlobal, 'b')), 'aa'.replace(nonGlobal, 'b'));
var uu = /(?:)/g;
Object.defineProperty(uu, 'flags', { value: 'gu' });
console.log(JSON.stringify('\u{1F600}'.match(uu)), JSON.stringify('\u{1F600}'.match(/(?:)/gu)));"##;
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
            r##"["x",""] flags,set li 0,exec,exec,get li,set li 1,exec"##,
            r##"bbXa bbXa ["a","a"] ["a"]"##,
            r##"TypeError ba"##,
            r##"["",""] ["",""]"##,
        ]
    );
}
