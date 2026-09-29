//! BigInt64Array and BigUint64Array (ES2020 22.2, bd-9vouw.80).
//!
//! Neither constructor existed: `new BigInt64Array(1)` failed with
//! "BigInt64Array is not defined", and 26 of the 1,443 Node-calibrated
//! Test262 sample tests failed on it. Elements read as BigInt values; writes
//! convert with ToBigInt (TypeError for a Number, SyntaxError for a string
//! that is not a BigInt literal) and wrap to 64 bits; a BigInt array never
//! mixes with a Number one. Expected values are Node v22.2.0's completion
//! values for the same programs (`vm.runInThisContext`).

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
fn construct_read_and_wrap() {
    check(
        r#"const a = new BigInt64Array([1n, -2n, 2n ** 63n, 2n ** 64n + 5n]);
const u = new BigUint64Array([1n, -1n, 2n ** 64n + 7n]);
[a.length, a[0], a[1], a[2], a[3], u[0], u[1], u[2], BigInt64Array.BYTES_PER_ELEMENT, typeof a[0]].join(' ')"#,
        "4 1 -2 -9223372036854775808 5 1 18446744073709551615 7 8 bigint",
    );
}

#[test]
fn writes_convert_with_to_bigint() {
    check(
        r#"const a = new BigInt64Array(3);
a[0] = 5n; a[1] = true; a[2] = '12';
let t = ''; try { a[0] = 1; } catch (e) { t = e.constructor.name; }
let s = ''; try { a[0] = 'x'; } catch (e) { s = e.constructor.name; }
[a.join(), t, s].join(' ')"#,
        "5,1,12 TypeError SyntaxError",
    );
}

#[test]
fn sort_join_and_search() {
    check(
        r#"const a = new BigInt64Array([3n, -2n, 10n, 0n]);
a.sort();
[a.join(), a.toString(), a.indexOf(10n), a.includes(-2n), a.includes(-2), a.at(-1)].join(' ')"#,
        "-2,0,3,10 -2,0,3,10 3 true false 10",
    );
}

#[test]
fn fill_set_map_filter() {
    check(
        r#"const a = new BigUint64Array(4);
a.fill(9n, 1, 3);
const b = new BigUint64Array(2);
b.set([4n, 5n]);
const m = a.map(x => x * 2n);
const f = a.filter(x => x > 0n);
[a.join(), b.join(), m.join(), Object.prototype.toString.call(m), f.length].join(' ')"#,
        "0,9,9,0 4,5 0,18,18,0 [object BigUint64Array] 2",
    );
}

#[test]
fn shared_buffer_views() {
    check(
        r#"const buf = new ArrayBuffer(16);
const a = new BigInt64Array(buf);
const u = new BigUint64Array(buf, 8, 1);
const d = new DataView(buf);
a[0] = -1n;
d.setBigInt64(8, 255n, true);
[u[0], new Uint8Array(buf)[0], new Uint8Array(buf)[8], a.subarray(1).join()].join(' ')"#,
        "255 255 255 255",
    );
}

#[test]
fn no_mixing_with_number_arrays() {
    check(
        r#"const out = [];
try { new Int8Array(new BigInt64Array(1)); } catch (e) { out.push(e.constructor.name); }
try { new BigInt64Array(new Int8Array(1)); } catch (e) { out.push(e.constructor.name); }
try { new BigInt64Array(2).set(new Float64Array(1)); } catch (e) { out.push(e.constructor.name); }
try { new BigInt64Array([1]); } catch (e) { out.push(e.constructor.name); }
out.push(new BigInt64Array(new BigUint64Array([2n ** 64n - 1n]))[0]);
out.join(' ')"#,
        "TypeError TypeError TypeError TypeError -1",
    );
}

#[test]
fn constructors_are_values() {
    check(
        r#"[typeof BigInt64Array, typeof BigUint64Array, BigInt64Array.name, BigUint64Array.length, Object.prototype.toString.call(new BigUint64Array(0))].join(' ')"#,
        "function function BigInt64Array 3 [object BigUint64Array]",
    );
}
