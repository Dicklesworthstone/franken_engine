//! Regression: the `Reflect` and `Proxy` meta-globals must be usable from
//! `HybridRouter::eval`.
//!
//! Bead: bd-v93ds (found by OliveLake eval-probe2). REPRO (`HybridRouter::eval`):
//! `Reflect.has({a:1},"a")` faulted "expected object, got undefined" (Reflect
//! undefined); `Reflect.ownKeys({a:1,b:2}).length` likewise; `new Proxy({x:5},{})`
//! faulted "expected function, got undefined" (Proxy not a constructor). Same
//! bare-global-resolution family as Date (bd-cseei) / Symbol / Map/Set.
//!
//! The Reflect/Proxy machinery already existed in the baseline interpreter
//! (`builtin:Reflect*`, `builtin:Proxy`, `proxy_aware_*`); the fix wires the
//! lowering interception so eval reaches it.

use frankenengine_engine::HybridRouter;

fn eval_value(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERR:{err}"),
    }
}

#[test]
fn reflect_has_detects_own_property() {
    assert_eq!(eval_value(r#"Reflect.has({a:1}, "a")"#), "true");
}

#[test]
fn reflect_has_false_for_missing_property() {
    assert_eq!(eval_value(r#"Reflect.has({a:1}, "b")"#), "false");
}

#[test]
fn reflect_own_keys_counts_own_properties() {
    assert_eq!(eval_value("Reflect.ownKeys({a:1, b:2}).length"), "2");
}

#[test]
fn proxy_empty_handler_passes_through_get() {
    assert_eq!(eval_value("new Proxy({x:5}, {}).x"), "5");
}

// ---- bd-9trje: enumeration consumers honor the ownKeys + getOwnPropertyDescriptor traps ----

#[test]
fn object_enumeration_consumers_honor_proxy_traps_bd_9trje() {
    // The Proxy target owns a,b,c; getOwnPropertyDescriptor marks b non-enumerable.
    // Object.keys/values/entries must consult the ownKeys trap for the key set AND
    // the getOwnPropertyDescriptor trap for per-key enumerability, while
    // getOwnPropertyNames returns every own String key regardless of enumerability.
    let setup = "const target = { a: 1, b: 2, c: 3 };\
                 const handler = {\
                     ownKeys(t) { return Reflect.ownKeys(t); },\
                     getOwnPropertyDescriptor(t, k) {\
                         return { value: t[k], enumerable: k !== 'b', configurable: true };\
                     }\
                 };\
                 const p = new Proxy(target, handler);";

    assert_eq!(
        eval_value(&format!("{setup} Object.keys(p).join(',')")),
        "a,c",
        "Object.keys omits the non-enumerable proxy key"
    );
    assert_eq!(
        eval_value(&format!("{setup} Object.getOwnPropertyNames(p).join(',')")),
        "a,b,c",
        "getOwnPropertyNames returns every own string key surfaced by ownKeys"
    );
    assert_eq!(
        eval_value(&format!("{setup} Object.values(p).join(',')")),
        "1,3",
        "Object.values reads enumerable proxy keys through [[Get]]"
    );
    assert_eq!(
        eval_value(&format!(
            "{setup} Object.entries(p).map(function(e){{ return e[0] + ':' + e[1]; }}).join(',')"
        )),
        "a:1,c:3",
        "Object.entries pairs enumerable proxy keys with their [[Get]] values"
    );
}

#[test]
fn object_keys_on_trapless_proxy_falls_through_to_target_bd_9trje() {
    // No ownKeys/descriptor traps: the enumeration must fall through to the target.
    assert_eq!(
        eval_value("Object.keys(new Proxy({ x: 5, y: 6 }, {})).join(',')"),
        "x,y"
    );
}

#[test]
fn for_in_enumerates_proxy_keys_through_traps_bd_9trje() {
    // for-in over a Proxy yields its enumerable own String keys via the ownKeys
    // + getOwnPropertyDescriptor traps ('b' is marked non-enumerable).
    let src = "const target = { a: 1, b: 2 };\
               const handler = {\
                   ownKeys(t) { return Reflect.ownKeys(t); },\
                   getOwnPropertyDescriptor(t, k) {\
                       return { value: t[k], enumerable: k !== 'b', configurable: true };\
                   }\
               };\
               const p = new Proxy(target, handler);\
               let out = [];\
               for (const k in p) { out.push(k); }\
               out.join(',');";
    assert_eq!(eval_value(src), "a");
}
