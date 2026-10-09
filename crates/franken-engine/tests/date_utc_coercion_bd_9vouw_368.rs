//! bd-9vouw.368: Date.UTC ToNumbers each argument in order (ES2020
//! 20.4.3.4): an object's valueOf runs and its number counts, a Symbol or
//! BigInt is a TypeError, and a throwing valueOf stops the call. An object
//! argument counted as NaN without running valueOf. The constructor and
//! setters are checked alongside. The line is Node v22.2.0's (Bun 1.4.2
//! agrees).

use frankenengine_engine::HybridRouter;

#[test]
fn date_utc_converts_each_argument_in_order() {
    let source = r#"
var out = [];
function t(name, f) { try { out.push(name + '=' + f()); } catch (e) { out.push(name + '!' + e.constructor.name); } }
var log = [];
function v(name, value) { return { valueOf: function () { log.push(name); return value; } }; }
t('utc-order', function () { log = []; var r = Date.UTC(v('y', 2020), v('m', 1), v('d', 2), v('h', 3), v('mi', 4), v('s', 5), v('ms', 6)); return r + ':' + log.join(','); });
t('utc-date-objs', function () { return Date.UTC(new Date(Date.UTC(2020, 0, 1)).getUTCFullYear(), 0); });
t('utc-string-args', function () { return Date.UTC('2020', '1'); });
t('ctor-order', function () { log = []; var d = new Date(v('y', 2020), v('m', 1)); return d.getFullYear() + ':' + log.join(','); });
t('setfullyear', function () { log = []; var d = new Date(0); d.setUTCFullYear(v('y', 2000), v('m', 1)); return d.getUTCFullYear() + ':' + log.join(','); });
t('utc-nan-continues', function () { log = []; var r = Date.UTC(NaN, v('m', 1)); return r + ':' + log.join(','); });
t('utc-symbol', function () { return Date.UTC(2020, Symbol()); });
t('utc-bigint', function () { return Date.UTC(1n); });
t('utc-throwing', function () { log = []; try { Date.UTC(v('y', 1), { valueOf: function () { throw new RangeError('x'); } }, v('d', 1)); } catch (e) { return e.constructor.name + ':' + log.join(','); } });
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
            "utc-order=1580612645006:y,m,d,h,mi,s,ms utc-date-objs=1577836800000 utc-string-args=1580515200000 ctor-order=2020:y,m setfullyear=2000:y,m utc-nan-continues=NaN:m utc-symbol!TypeError utc-bigint!TypeError utc-throwing=RangeError:y",
        ]
    );
}
