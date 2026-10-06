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
