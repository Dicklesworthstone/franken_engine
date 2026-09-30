//! BRIDGE-15.24 (slice): all nine non-BigInt ES2020 TypedArray kinds, with
//! their element conversions, and the binary-data constructors as values.
//!
//! Only Uint8/Int32/Uint32 existed; `Float64Array` & co. were "not defined",
//! which failed every Test262 test that includes harness/testTypedArray.js at
//! load (it lists all nine constructors). Expected strings are what Node
//! v22.2.0 prints for the same programs.
//!
//! The kind tests read elements back by index; `typed_arrays_have_the_array_methods`
//! covers the %TypedArray%.prototype methods, which all used to throw
//! "unsupported TypedArray method".
//!
//! No mocks: real source through the public `HybridRouter::eval` path.

use frankenengine_engine::HybridRouter;

fn eval_to_string(source: &str) -> String {
    match HybridRouter::default().eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERROR: {err:?}"),
    }
}

fn check(source: &str, node: &str) {
    assert_eq!(
        eval_to_string(source),
        node,
        "`{source}` must match Node v22.2.0"
    );
}

#[test]
fn float_arrays_store_numbers() {
    check(
        "const a = new Float64Array(3); a[1] = 1.5; a.length + ':' + a[1] + ':' + a[0];",
        "3:1.5:0",
    );
    // Float32 rounds through single precision.
    check("new Float32Array([1.1])[0];", "1.100000023841858");
}

#[test]
fn integer_arrays_wrap_modulo_their_width() {
    check(
        "const a = new Int8Array([127, 128, -129, 1.9]); [a[0], a[1], a[2], a[3]].join();",
        "127,-128,127,1",
    );
    check(
        "const i = new Int16Array([70000, -32769]); const u = new Uint16Array([-1, 65536]); \
         [i[0], i[1]].join() + '|' + [u[0], u[1]].join();",
        "4464,32767|65535,0",
    );
}

#[test]
fn uint8_clamped_rounds_half_to_even_and_clamps() {
    check(
        "const c = new Uint8ClampedArray([-5, 300, 1.5, 2.5, 254.5]); [c[0], c[1], c[2], c[3], c[4]].join();",
        "0,255,2,2,254",
    );
}

#[test]
fn binary_constructors_are_values() {
    check(
        "[typeof Float64Array, typeof Uint8ClampedArray, typeof ArrayBuffer, typeof DataView].join();",
        "function,function,function,function",
    );
    check("const C = Uint8Array; new C([1, 2, 300])[2];", "44");
    // The shape of harness/testTypedArray.js: constructors held in an array.
    check(
        "const cs = [Float64Array, Float32Array, Int32Array, Int16Array, Int8Array, \
         Uint32Array, Uint16Array, Uint8Array, Uint8ClampedArray]; \
         cs.map(C => new C(2).length).join();",
        "2,2,2,2,2,2,2,2,2",
    );
    check(
        "Float64Array.name + ':' + Float64Array.length + ':' + Int8Array.BYTES_PER_ELEMENT;",
        "Float64Array:3:1",
    );
}

/// ES2020 22.2.3: join / toString / indexOf / lastIndexOf / includes / at /
/// forEach / reduce / reduceRight / find / findIndex / some / every behave as
/// their Array.prototype namesakes; map and filter build a typed array of the
/// receiver's kind (map converts: 300 wraps to 44 in a Uint8Array); reverse
/// and sort reorder in place (a subarray view only its own window), and sort
/// without a comparator is numeric (-0 before 0, NaN last).
#[test]
fn typed_arrays_have_the_array_methods() {
    check(
        r#"const a = new Uint8Array([3, 1, 2]);
const r = [];
r.push(a.join('-'), a.toString(), String(a), `${a}`, a + '', a.indexOf(1), a.lastIndexOf(9), a.includes(2), a.at(-1));
let s = 0; a.forEach((x, i, o) => { s += x * (i + 1); r.push(o === a); });
r.push(s, a.reduce((p, x) => p + x, 0), a.reduceRight((p, x) => p + String(x), ''), a.find(x => x < 3), a.findIndex(x => x === 2), a.some(x => x > 2), a.every(x => x > 0));
const m = a.map(x => x * 100);
r.push(Object.prototype.toString.call(m), m.join(), a.filter(x => x !== 1).join(), Object.prototype.toString.call(a.filter(() => true)));
r.push(a.reverse() === a, a.join(), a.sort().join(), new Uint8Array([10, 9, 1, 100]).sort().join(), new Int8Array([5, -3, 0]).sort((x, y) => y - x).join());
const f = new Float64Array([2.5, NaN, -0, 0, -1]);
r.push(Array.from(f.sort()).map(x => Object.is(x, -0) ? '-0' : String(x)).join(), new Float32Array([1.5, 2]).map(x => x / 2).join());
const big = new Uint8Array([1, 2, 3, 4, 5]); big.subarray(1, 4).reverse(); r.push(big.join());
let threw; try { a.map(0); threw = 'no'; } catch (e) { threw = e instanceof TypeError; } r.push(threw);
r.join(' ');"#,
        "3-1-2 3,1,2 3,1,2 3,1,2 3,1,2 1 -1 true 2 true true true 11 6 213 1 2 true true \
         [object Uint8Array] 44,100,200 3,2 [object Uint8Array] true 2,1,3 1,2,3 1,9,10,100 5,0,-3 \
         -1,-0,0,2.5,NaN 0.75,1 1,4,3,2,5 true",
    );
}

#[test]
fn a_symbol_or_bigint_from_index_throws_a_type_error() {
    // ToIntegerOrInfinity(fromIndex) throws for a Symbol or BigInt. Arrays
    // read it as 0; typed arrays reach the same generic search methods, and
    // Test262 TypedArray/prototype/indexOf/return-abrupt-tointeger-fromindex-symbol
    // expects the throw.
    let probe = |call: &str| {
        format!(
            "(() => {{ try {{ {call}; return 'no throw'; }} catch (e) {{ return e.name; }} }})()"
        )
    };
    for call in [
        "[1, 2].indexOf(7, Symbol('1'))",
        "[1, 2].includes(7, Symbol('1'))",
        "[1, 2].lastIndexOf(7, Symbol('1'))",
        "[1, 2].indexOf(7, 1n)",
        "new Float64Array(1).indexOf(7, Symbol('1'))",
    ] {
        check(&probe(call), "TypeError");
    }
    check("[1, 2, 1].indexOf(1, 1)", "2");
}
