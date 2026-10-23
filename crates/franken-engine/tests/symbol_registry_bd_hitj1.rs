//! bd-hitj1 — Symbol.for / Symbol.keyFor global registry.
//!
//! `Symbol.for(key)` interns one symbol per string key (so two calls with the
//! same key are identical), while a fresh `Symbol()` is never registry-interned.
//! `Symbol.keyFor(sym)` returns the registry key, or undefined for a
//! non-registered symbol. Follow-up to bd-bn1z7 (Symbol() + typeof).

use frankenengine_engine::HybridRouter;

fn eval(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERR:{err}"),
    }
}

#[test]
fn for_same_key_is_identical() {
    assert_eq!(eval("Symbol.for('x') === Symbol.for('x');"), "true");
}

#[test]
fn for_different_keys_differ() {
    assert_eq!(eval("Symbol.for('a') === Symbol.for('b');"), "false");
}

#[test]
fn fresh_symbol_is_not_registry_interned() {
    assert_eq!(eval("Symbol.for('y') === Symbol('y');"), "false");
}

#[test]
fn key_for_returns_registry_key() {
    assert_eq!(eval("Symbol.keyFor(Symbol.for('z'));"), "z");
}

#[test]
fn key_for_unregistered_is_undefined() {
    assert_eq!(eval("typeof Symbol.keyFor(Symbol('w'));"), "undefined");
}

#[test]
fn registered_symbol_is_a_symbol() {
    assert_eq!(eval("typeof Symbol.for('t');"), "symbol");
}

#[test]
fn mixed_symbol_population_preserves_registry_identity() {
    // Same source returns true in Node. Private symbols with equal descriptions
    // must never enter the registry, regardless of their allocation order.
    assert_eq!(
        eval(
            r#"
            const saved = [];
            for (let i = 0; i < 512; i++) {
                Symbol('key-' + i);
                saved.push(Symbol.for('key-' + i));
                Symbol('key-' + i);
            }
            let valid = true;
            for (let i = saved.length - 1; i >= 0; i--) {
                valid = valid && saved[i] === Symbol.for('key-' + i);
                valid = valid && Symbol.keyFor(saved[i]) === 'key-' + i;
                valid = valid && saved[i] !== Symbol('key-' + i);
            }
            valid;
            "#,
        ),
        "true"
    );
}

#[test]
fn registry_keys_preserve_lone_surrogates_and_replacement_characters() {
    assert_eq!(
        eval(
            r#"
            const high = Symbol.for('\ud800');
            const other = Symbol.for('\ud801');
            const low = Symbol.for('\udc00');
            const replacement = Symbol.for('\ufffd');
            high !== other && high !== replacement && other !== replacement
                && low !== high && low !== other && low !== replacement
                && high === Symbol.for('\ud800')
                && other === Symbol.for('\ud801')
                && low === Symbol.for('\udc00')
                && Symbol.keyFor(high).charCodeAt(0) === 55296
                && Symbol.keyFor(other).charCodeAt(0) === 55297
                && Symbol.keyFor(low).charCodeAt(0) === 56320;
            "#,
        ),
        "true"
    );
}

#[test]
fn equivalent_rope_and_flat_registry_keys_share_identity() {
    assert_eq!(
        eval(
            r#"
            let key = '';
            for (let i = 0; i < 64; i++) key += 'prefix-';
            const first = Symbol.for(key + 'a');
            const second = Symbol.for(key + 'b');
            first !== second
                && first === Symbol.for('prefix-'.repeat(64) + 'a')
                && second === Symbol.for('prefix-'.repeat(64) + 'b')
                && Symbol.keyFor(first) === key + 'a';
            "#,
        ),
        "true"
    );
}
