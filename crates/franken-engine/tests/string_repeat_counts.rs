#![forbid(unsafe_code)]

//! String.prototype.repeat with a count of +Infinity throws a RangeError for
//! every receiver (ES2020 21.1.3.16 step 4): "".repeat(Infinity) returned ""
//! because the saturated count passed the result-length guard (Test262
//! String/prototype/repeat/count-is-infinity-throws.js). Negative, fractional
//! and NaN counts keep their behavior.

use frankenengine_engine::HybridRouter;

/// Expected line is Node v22.2.0's output, captured programmatically from the
/// same source.
#[test]
fn repeat_counts_match_node() {
    let source = r#"function k(f) { try { return JSON.stringify(f()); } catch (e) { return e.constructor.name; } }
console.log(k(function () { return "x".repeat(Infinity); }), k(function () { return "".repeat(Infinity); }), k(function () { return "ab".repeat(-1); }), k(function () { return "ab".repeat(2.9); }), k(function () { return "ab".repeat(NaN); }), k(function () { return "".repeat(1e10); }));
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
        ["RangeError RangeError RangeError \"abab\" \"\" \"\"",]
    );
}

fn console_lines(source: &str) -> Vec<String> {
    HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .console_output
        .into_iter()
        .map(|entry| entry.message)
        .collect()
}

// Expected console lines were checked against native V8 using each exact
// source below. These cases exercise observable conversion order as well as
// exact UTF-16 units; lossy UTF-8 equality cannot establish conformance.

#[test]
fn repetition_preserves_exact_units_and_heals_only_adjacent_surrogates() {
    let source = r#"function units(value) {
    var result = [];
    for (var i = 0; i < value.length; i++) result.push(value.charCodeAt(i));
    return result.join(",");
}
console.log(units("\ud800".repeat(3)));
console.log(units("\udc00\ud800".repeat(3)));
console.log(units("😀".repeat(2)));
console.log(units("\ud800a\udc00".repeat(2)));
console.log("".repeat(1e100).length);
console.log("\ud800".repeat(0).length, "\ud800".repeat(1).charCodeAt(0));
"#;
    assert_eq!(
        console_lines(source),
        [
            "55296,55296,55296",
            "56320,55296,56320,55296,56320,55296",
            "55357,56832,55357,56832",
            "55296,97,56320,55296,97,56320",
            "0",
            "0 55296",
        ]
    );
}

#[test]
fn padding_observes_length_before_fill_and_preserves_exact_units() {
    let source = r#"var seen = 0;
var unused = { toString: function () { seen++; throw new Error("unused fill"); } };
console.log("abc".padStart(2, unused), "abc".padEnd(3, unused), seen);
console.log("abc".padStart(2, Symbol()), "abc".padEnd(3, Symbol()));
var order = [];
var length = { valueOf: function () { order.push("length"); return 5; } };
var fill = { toString: function () { order.push("fill"); return "xy"; } };
console.log("a".padStart(length, fill), order.join(","));
console.log("abc".padStart(Infinity, "").length);
var pair = "\udc00".padStart(2, "\ud800");
console.log(pair.length, pair.codePointAt(0), "\ud800".padEnd(2, "\udc00").codePointAt(0));
var truncated = "x".padStart(4, "😀");
console.log(truncated.length, truncated.charCodeAt(2), truncated.charCodeAt(3));
var undefinedFill = { toString: function () { return undefined; } };
console.log(JSON.stringify("x".padStart(4, undefinedFill)), JSON.stringify("x".padStart(4, undefined)));
var start = "\udc00".padStart(17, "\udc00\ud800");
var end = "\ud800".padEnd(17, "\udc00\ud800");
console.log(start.length, start.codePointAt(1), start.charCodeAt(16), end.length, end.codePointAt(0), end.charCodeAt(16));
"#;
    assert_eq!(
        console_lines(source),
        [
            "abc abc 0",
            "abc abc",
            "xyxya length,fill",
            "3",
            "2 65536 65536",
            "4 55357 120",
            "\"undx\" \"   x\"",
            "17 65536 56320 17 65536 55296",
        ]
    );
}

#[test]
fn expansion_converts_receivers_once_before_arguments() {
    let source = r#"var order = [];
var receiver = { [Symbol.toPrimitive]: function (hint) { order.push("receiver:" + hint); return "\ud800"; } };
var count = { valueOf: function () { order.push("count"); return 2; } };
var repeated = String.prototype.repeat.call(receiver, count);
console.log(repeated.length, repeated.charCodeAt(1), order.join(","));
order = [];
var fill = { toString: function () { order.push("fill"); return "x"; } };
var padded = String.prototype.padEnd.call(receiver, count, fill);
console.log(padded.charCodeAt(0), padded.charCodeAt(1), order.join(","));
console.log(String.prototype.repeat.call({ toString: function () { return null; } }, 2));
console.log(String.prototype.padStart.call({ toString: function () { return undefined; } }, 10, "."));
var boxed = new String("original");
boxed.toString = function () { return "overridden"; };
console.log(boxed.repeat(2), boxed.padStart(11, "."), String.prototype.toString.call(boxed));
function typeError(value) {
    try { String.prototype.repeat.call(value, 1); return false; }
    catch (error) { return error instanceof TypeError; }
}
console.log(typeError(null), typeError(Symbol()));
"#;
    assert_eq!(
        console_lines(source),
        [
            "2 55296 receiver:string,count",
            "55296 120 receiver:string,count,fill",
            "nullnull",
            ".undefined",
            "overriddenoverridden .overridden original",
            "true true",
        ]
    );
}
