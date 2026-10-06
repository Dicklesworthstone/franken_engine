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
