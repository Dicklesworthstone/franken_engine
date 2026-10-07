//! bd-9vouw.338: an Array's `length` set or defined to an object converts
//! it (ES2020 9.4.2.4 ArraySetLength steps 3-5: ToUint32, then ToNumber, so
//! valueOf runs twice; a RangeError when they differ). `arr.length = new
//! Number(6)`, `arr.length = { valueOf }` and Object.defineProperties with
//! an object `length` value failed with an uncatchable "invalid array length
//! object"; Object.defineProperty already converted. The program also keeps
//! a frozen array's length unconverted (OrdinarySet rejects the write before
//! ArraySetLength), a throwing valueOf catchable, and a fractional or
//! changing result a RangeError. Node v22.2.0 gives this line.

use frankenengine_engine::HybridRouter;

#[test]
fn an_object_array_length_converts_through_value_of() {
    let source = r#"
var out = [];
var x = [];
x[1] = 1; x[3] = 3; x[5] = 5;
x.length = 4;
x.length = new Number(6);
out.push(x.length, x[5], x[3]);
var calls = 0;
var y = [1, 2, 3];
y.length = { valueOf: function () { calls++; return 1; } };
out.push(y.length, calls);
var z = [];
z.length = { valueOf: function () { return 2; }, toString: function () { return 1; } };
out.push(z.length);
try { z.length = { valueOf: function () { return 1.5; } }; out.push('no'); } catch (e) { out.push(e instanceof RangeError); }
try { z.length = { valueOf: function () { throw 'thrown'; } }; out.push('no'); } catch (e) { out.push(e); }
var flip = 0;
try { z.length = { valueOf: function () { flip++; return flip === 1 ? 3 : 4; } }; out.push('no'); } catch (e) { out.push(e instanceof RangeError, flip); }
var frozenCalls = 0;
var f = Object.freeze([1, 2]);
f.length = { valueOf: function () { frozenCalls++; return 0; } };
out.push(f.length, frozenCalls);
var d = [];
var seen = [];
Object.defineProperties(d, { length: { value: { toString: function () { seen.push('toString'); return '2'; }, valueOf: function () { seen.push('valueOf'); return 3; } } } });
out.push(d.length, seen.join('+'));
var e = [];
Object.defineProperties(e, { length: { value: { toString: function () { return '2'; } } } });
out.push(e.length);
var g = [];
Object.defineProperty(g, 'length', { value: new Number(4) });
out.push(g.length);
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
        ["6  3 1 2 2 true thrown true 2 2 0 3 valueOf+valueOf 2 4"]
    );
}
