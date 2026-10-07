#![forbid(unsafe_code)]

//! bd-9vouw.245: Atomics (ES2020 24.4) was not defined. About 125
//! Node-passing Test262 tests failed with "Atomics is not defined".
//!
//! PROGRAM checks:
//! - the namespace (toStringTag, lengths, names, no enumerable keys);
//! - every read-modify-write on Int32/Uint8/BigInt64/BigUint64 arrays,
//!   with wrapping;
//! - store's ToIntegerOrInfinity result (-0 is +0, 2^33 + 1 kept, strings
//!   and valueOf converted);
//! - BigInt arrays refusing Numbers;
//! - isLockFree;
//! - TypeErrors for float, clamped and non-typed-array targets;
//! - RangeErrors for bad indices;
//! - notify (0 waiters);
//! - wait: not-equal, timed-out with a zero timeout, non-shared and
//!   non-waitable arrays refused, and a 40 ms timeout after which Date.now
//!   has advanced at least 40 ms.
//!
//! Expected lines are Node v22.2.0's output, captured programmatically.
//!
//! No-claim: one agent runs. A finite wait advances the deterministic clock
//! instead of blocking; an infinite one (no agent can notify) is refused
//! with a TypeError where Node would block forever. waitAsync is not
//! provided.

use frankenengine_engine::HybridRouter;

#[test]
fn atomics_match_node_bd_9vouw_245() {
    let source = r#"function attempt(f) { try { return String(f()); } catch (e) { return e.constructor.name; } }
var i32 = new Int32Array(new SharedArrayBuffer(16));
console.log(typeof Atomics, Object.prototype.toString.call(Atomics), Atomics.add.length, Atomics.compareExchange.length, Atomics.wait.name, Object.keys(Atomics).length);
console.log(Atomics.store(i32, 0, 7), Atomics.add(i32, 0, 5), Atomics.load(i32, 0), Atomics.sub(i32, 0, 20), Atomics.load(i32, 0), Atomics.and(i32, 0, 6), Atomics.or(i32, 0, 1), Atomics.xor(i32, 0, 3), Atomics.load(i32, 0));
console.log(Atomics.exchange(i32, 1, 9), Atomics.compareExchange(i32, 1, 9, 4), Atomics.compareExchange(i32, 1, 9, 5), Atomics.load(i32, 1));
console.log(Atomics.store(i32, 2, 3.9), Atomics.store(i32, 2, -0), Object.is(Atomics.store(i32, 2, -0), 0), Atomics.store(i32, 2, 2 ** 33 + 1), Atomics.load(i32, 2), Atomics.store(i32, 2, '12'), Atomics.add(i32, 2, { valueOf() { return 1; } }));
var u8 = new Uint8Array(4);
console.log(Atomics.add(u8, 0, 300), u8[0], Atomics.sub(u8, 1, 1), u8[1], Atomics.store(u8, 2, -1), u8[2]);
var big = new BigInt64Array(new SharedArrayBuffer(16));
console.log(Atomics.store(big, 0, 5n), Atomics.add(big, 0, 2n ** 64n + 1n), Atomics.load(big, 0), Atomics.sub(big, 1, 1n), Atomics.load(big, 1), attempt(() => Atomics.add(big, 0, 1)));
var ubig = new BigUint64Array(2);
console.log(Atomics.sub(ubig, 0, 1n), Atomics.load(ubig, 0), Atomics.compareExchange(ubig, 0, -1n, 3n), ubig[0]);
console.log(Atomics.isLockFree(1), Atomics.isLockFree(2), Atomics.isLockFree(3), Atomics.isLockFree(4), Atomics.isLockFree(8));
console.log(attempt(() => Atomics.add(new Float64Array(2), 0, 1)), attempt(() => Atomics.load(new Uint8ClampedArray(2), 0)), attempt(() => Atomics.load(i32, 4)), attempt(() => Atomics.load(i32, -1)), attempt(() => Atomics.load({}, 0)), attempt(() => Atomics.load(i32, '1')));
console.log(Atomics.notify(i32, 0), Atomics.notify(i32, 0, 2), attempt(() => Atomics.notify(new Int16Array(new SharedArrayBuffer(4)), 0)), Atomics.notify(new Int32Array(4), 0));
console.log(Atomics.wait(i32, 0, 1, 0), Atomics.wait(i32, 0, Atomics.load(i32, 0), 0), attempt(() => Atomics.wait(new Int32Array(4), 0, 0, 0)), attempt(() => Atomics.wait(new Uint32Array(new SharedArrayBuffer(4)), 0, 0, 0)));
var t0 = Date.now();
console.log(Atomics.wait(i32, 3, 0, 40), Date.now() - t0 >= 40, Atomics.wait(big, 1, -1n, 1));"#;
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
            r#"object [object Atomics] 3 4 wait 0"#,
            r#"7 7 12 12 -8 -8 0 1 2"#,
            r#"0 9 4 4"#,
            r#"3 0 true 8589934593 1 12 12"#,
            r#"0 44 0 255 -1 255"#,
            r#"5n 5n 6n 0n -1n TypeError"#,
            r#"0n 18446744073709551615n 18446744073709551615n 3n"#,
            r#"true true false true true"#,
            r#"TypeError TypeError RangeError RangeError TypeError 4"#,
            r#"0 0 TypeError 0"#,
            r#"not-equal timed-out TypeError TypeError"#,
            r#"timed-out true timed-out"#,
        ]
    );
}
