//! bd-9vouw.305: ArraySpeciesCreate's ArrayCreate(length) throws a
//! RangeError for a length past 2^32 - 1 before the method touches any
//! element.
//!
//! The generic path for an array-like or a Proxy made its result without
//! that check, so `slice`, `map` and `splice` of one reporting a length of
//! 2^32 walked 2^32 indexes until the instruction budget ran out. The last
//! case slices the top two indexes of a 2^32 - 1 length array-like, which
//! must still work. Node v22.2.0 gives this value; Bun 1.4.2 agrees.

use frankenengine_engine::HybridRouter;

#[test]
fn species_array_create_refuses_lengths_past_u32_before_touching_elements() {
    let source = r#"
var out = [];
function attempt(f) { try { f(); return 'none'; } catch (e) { return e.constructor.name; } }
var big = Math.pow(2, 32);
var setCount = 0;
var like = Object.defineProperty({}, 'length', { get: function () { return big; }, set: function () { setCount++; } });
out.push(attempt(function () { Array.prototype.slice.call(like); }));
var array = [];
var cbCount = 0;
var proxy = new Proxy(array, { get: function (_, name) { return name === 'length' ? big : array[name]; }, set: function () { setCount++; return true; } });
out.push(attempt(function () { Array.prototype.map.call(proxy, function () { cbCount++; }); }));
out.push(attempt(function () { Array.prototype.splice.call(like, 0); }));
var tail = Array.prototype.slice.call({ length: big - 1, 4294967293: 'a' }, big - 3);
out.push(tail.length, tail[0], setCount, cbCount);
out.join(' ');
"#;
    let value = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .value;
    assert_eq!(value, "RangeError RangeError RangeError 2 a 0 0");
}
