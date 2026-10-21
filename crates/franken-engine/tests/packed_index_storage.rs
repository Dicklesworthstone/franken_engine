//! Real parse/lower/execute coverage for the shared packed property carrier.
#![forbid(unsafe_code)]

use frankenengine_engine::HybridRouter;

fn check(source: &str, expected: &[&str]) {
    let actual: Vec<String> = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .console_output
        .into_iter()
        .map(|entry| entry.message)
        .collect();
    assert_eq!(actual, expected, "source: {source}");
}

#[test]
fn dense_moves_and_holes_preserve_values_identity_and_named_keys() {
    check(
        r#"
        const shared = { x: 3 };
        const a = [-0, NaN, shared];
        a.z = 'last';
        a.a = 'after';
        console.log(Object.is(a[0], -0), Number.isNaN(a[1]),
            a[2] === shared, a.length, Object.keys(a).join(','));
        delete a[1];
        console.log(1 in a, a[1] === undefined, a.length);
        a[1] = 5;
        console.log(a.splice(1, 1)[0], a[1] === shared, a.unshift(7));
        console.log(a.shift(), Object.is(a[0], -0), a[1] === shared);
        a.push(9);
        console.log(JSON.stringify(a), Object.keys(a).join(','), a.z, a.a);
        "#,
        &[
            "true true true 3 0,1,2,z,a",
            "false true 3",
            "5 true 3",
            "7 true true",
            "[0,{\"x\":3},9] 0,1,2,z,a last after",
        ],
    );
}

#[test]
fn sparse_promotion_and_length_shrink_preserve_non_index_keys() {
    check(
        r#"
        const a = ['zero'];
        a[2] = 'two';
        a[4294967294] = 'far';
        a[4294967295] = 'named';
        a['01'] = 'leading';
        a['-0'] = 'minus';
        console.log(a.length, a[4294967294], Object.keys(a).join(','));
        a.length = 2;
        console.log(a.length, 1 in a, 2 in a, 4294967294 in a,
            a[4294967295], a['01'], a['-0'], Object.keys(a).join(','));
        "#,
        &[
            "4294967295 far 0,2,4294967294,4294967295,01,-0",
            "2 false false false named leading minus 0,4294967295,01,-0",
        ],
    );
}

#[test]
fn inherited_and_accessor_elements_keep_observable_move_order() {
    check(
        r#"
        Array.prototype[1] = 20;
        const a = [1, , 3];
        console.log(a.map(x => x).join(','), a.hasOwnProperty(1));
        console.log(a.shift(), a.join(','), a.hasOwnProperty(0));
        delete Array.prototype[1];
        const events = [];
        const b = [10, 20, 30];
        Object.defineProperty(b, '1', {
            get() { events.push('get'); return 20; },
            set(value) { events.push('set:' + value); },
            configurable: true
        });
        const removed = b.shift();
        console.log(removed, b[0], b[1], b.length, 2 in b, events.join(','));
        "#,
        &[
            "1,20,3 false",
            "1 20,3 true",
            "10 20 20 2 false get,set:30,get",
        ],
    );
}

#[test]
fn frozen_and_locked_arrays_preserve_partial_failure_semantics() {
    check(
        r#"
        const frozen = Object.freeze([1, 2]);
        try { frozen.shift(); } catch (error) { console.log(error.name); }
        try { frozen.unshift(0); } catch (error) { console.log(error.name); }
        try { frozen.splice(0, 1); } catch (error) { console.log(error.name); }
        console.log(frozen.length, frozen.join(','));
        const locked = [1, 2, 3, 4];
        Object.defineProperty(locked, '2', { configurable: false });
        try {
            (function () { 'use strict'; locked.length = 1; })();
        } catch (error) { console.log(error.name); }
        console.log(locked.length, locked.join(','), 3 in locked, 2 in locked);
        const lengthLocked = [1, 2, 3];
        Object.defineProperty(lengthLocked, 'length', { writable: false });
        try { lengthLocked.shift(); } catch (error) { console.log(error.name); }
        console.log(lengthLocked.length, lengthLocked.join(','), 2 in lengthLocked);
        "#,
        &[
            "TypeError",
            "TypeError",
            "TypeError",
            "2 1,2",
            "TypeError",
            "3 1,2,3 false true",
            "TypeError",
            "3 2,3, false",
        ],
    );
}
