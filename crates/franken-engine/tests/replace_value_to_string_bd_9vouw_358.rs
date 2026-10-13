//! bd-9vouw.358: a replace value that is not callable, and a replacer's
//! result, are ToString'd observably (ES2020 21.1.3.17 steps 5 and 6.e,
//! 21.2.5.8 steps 6 and 14.l): an object's own toString (or valueOf) runs,
//! its throw is the call's, and a Symbol result is a TypeError. The shared
//! replace path stringified both without guest code, after matching, so a
//! direct `/re/[Symbol.replace](s, obj)` and every replacer returning an
//! object read "[object Object]", and a Symbol result was spliced in. The
//! line is Node v22.2.0's (Bun 1.4.2 agrees; the TypeError's message is not
//! compared).

use frankenengine_engine::HybridRouter;

#[test]
fn replace_values_and_replacer_results_are_stringified_observably() {
    let source = r#"
var out = [];
function t(name, f) { try { out.push(name + ':' + JSON.stringify(f())); } catch (e) { out.push(name + ':' + e.constructor.name + (e instanceof RangeError ? '(' + e.message + ')' : '')); } }
var obj = { toString: function () { return 'X'; } };
var log = [];
var valued = { toString: undefined, valueOf: function () { log.push('valueOf'); return 7; } };
t('str-replace-re-obj', function () { return 'string'.replace(/s/, obj); });
t('sym-replace-obj', function () { return /s/[Symbol.replace]('string', obj); });
t('sym-replace-valueof', function () { return /s/[Symbol.replace]('string', valued) + log.join(); });
t('fn-result-obj', function () { return 'string'.replace(/s/, function () { return obj; }); });
t('fn-result-str-obj', function () { return 'string'.replace('s', function () { return obj; }); });
t('sym-fn-result-obj', function () { return /s/g[Symbol.replace]('sas', function () { return obj; }); });
t('replaceAll-fn-obj', function () { return 'sas'.replaceAll('s', function () { return obj; }); });
t('fn-result-symbol', function () { return 'abc'.replace(/b/, function () { return Symbol('q'); }); });
t('fn-result-num', function () { return 'abc'.replace(/b/, function () { return 42; }); });
t('sym-replace-throw', function () { return /b/[Symbol.replace]('abc', { toString: function () { throw new RangeError('tostring'); } }); });
t('fn-result-throw', function () { return 'abc'.replace(/b/, function () { return { toString: function () { throw new RangeError('result'); } }; }); });
console.log(out.join(' '));
"#;
    let outcome = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"));
    let lines: Vec<&str> = outcome
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect();
    assert_eq!(
        lines,
        [
            "str-replace-re-obj:\"Xtring\" sym-replace-obj:\"Xtring\" sym-replace-valueof:\"7tringvalueOf\" fn-result-obj:\"Xtring\" fn-result-str-obj:\"Xtring\" sym-fn-result-obj:\"XaX\" replaceAll-fn-obj:\"XaX\" fn-result-symbol:TypeError fn-result-num:\"a42c\" sym-replace-throw:RangeError(tostring) fn-result-throw:RangeError(result)"
        ]
    );
}
