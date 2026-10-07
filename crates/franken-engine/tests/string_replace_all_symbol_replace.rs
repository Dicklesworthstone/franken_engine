#![forbid(unsafe_code)]

//! ES2021 22.1.3.19 String.prototype.replaceAll: a RegExp whose @@replace
//! is undefined or null is searched for as its ToString text ("/./g"), not
//! matched as a pattern. The engine matched it as a pattern (4 Node-passing
//! Test262 tests in the rc-next33 merged-tree census:
//! String/prototype/replaceAll/getSubstitution-0x0024{N,NN,-0x003C},
//! searchValue-tostring-regexp).

use frankenengine_engine::HybridRouter;

/// RegExps whose @@replace is undefined or null (their source text, a
/// program-defined toString), next to a pristine global RegExp and a
/// string search with a function replacement. Expected lines are Node
/// v22.2.0's output, captured programmatically.
#[test]
fn replace_all_searches_for_a_regexp_without_replace_as_text() {
    let source = r#"function custom(source) {
  var re = new RegExp(source, 'g');
  Object.defineProperty(re, Symbol.replace, { value: undefined });
  return re;
}
console.log('--- /./g --- /a/g --- /./g ---'.replaceAll(custom('.'), 'a($1$1)'), 'aa z z aa'.replaceAll(custom('.'), 'z'), 'x /x/g y'.replaceAll(custom('x'), '[$&]'));
var nulled = /b/g;
Object.defineProperty(nulled, Symbol.replace, { value: null });
var toStringed = /q/g;
Object.defineProperty(toStringed, Symbol.replace, { value: undefined });
toStringed.toString = function () { return 'b'; };
console.log('a/b/g c'.replaceAll(nulled, '!'), 'abcb'.replaceAll(toStringed, '-'), 'abab'.replaceAll(/b/g, '$&$&'), 'abab'.replaceAll('b', function (m, i) { return i; }));
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
            "--- a($1$1) --- /a/g --- a($1$1) --- aa z z aa x [/x/g] y",
            "a! c a-c- abbabb a1a3",
        ]
    );
}
