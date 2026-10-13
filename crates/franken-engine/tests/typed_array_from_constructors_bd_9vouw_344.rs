//! bd-9vouw.344: %TypedArray%.from and %TypedArray%.of take any constructor
//! as `this` (ES2020 22.2.2.1-2): a subclass builds its own instances, and
//! any constructor goes through TypedArrayCreate (constructed with the
//! length; the result must be a typed array at least that long). The engine
//! accepted only intrinsic typed array constructors. A mapper's value is
//! converted before the next is mapped, so a throwing valueOf stops it.
//! Also checked: a non-constructor `this`, a short or non-typed-array
//! result, and an array-like's length read before the constructor runs.
//! Node v22.2.0 gives this line.

use frankenengine_engine::HybridRouter;

#[test]
fn typed_array_from_and_of_construct_through_this() {
    let source = r#"
var out = [];
class Vec3 extends Float32Array {}
function t(name, f) { try { out.push(name + '=' + f()); } catch (e) { out.push(name + ':' + e.constructor.name); } }
t('subFrom', function () { var v = Vec3.from([1, 2, 3]); return [v instanceof Vec3, v.length, v[2]].join(','); });
t('subOf', function () { var v = Vec3.of(4, 5); return [v instanceof Vec3, v.length, v[1]].join(','); });
t('subMap', function () { var v = Vec3.from([1, 2], function (x) { return x * 10; }); return [v.constructor.name, v[1]].join(','); });
var custom = new Uint8Array(3);
t('ctorOther', function () { return Uint8Array.from.call(function () { return custom; }, [7, 8]) === custom && custom[1]; });
t('ctorShort', function () { return Uint8Array.from.call(function () { return new Uint8Array(1); }, [1, 2]); });
t('ctorNotTA', function () { return Uint8Array.from.call(function () { return {}; }, [1]); });
t('notCtor', function () { return Uint8Array.from.call(Math.max, [1]); });
var calls = [];
t('lenFirst', function () { return Uint8Array.from.call(function () { calls.push('ctor'); return new Uint8Array(2); }, { get length() { calls.push('len'); return 2; }, 0: 1, 1: 2 }).join() + '/' + calls.join(); });
var last;
var bad = { valueOf: function () { throw 'E'; } };
t('abrupt', function () { return Uint8Array.from([42, bad, 1], function (v) { last = v; return v; }); });
out.push(last === bad);
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
            "subFrom=true,3,3 subOf=true,2,5 subMap=Vec3,20 ctorOther=8 ctorShort:TypeError \
             ctorNotTA:TypeError notCtor:TypeError lenFirst=1,2/len,ctor abrupt:String true"
        ]
    );
}
