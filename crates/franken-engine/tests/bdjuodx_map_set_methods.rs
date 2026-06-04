//! bd-juodx regression: Map/Set prototype methods must be reachable via member
//! access. The method bodies existed as builtin hostcalls but weren't wired to
//! the GetProperty -> BuiltinFunction -> CallMethod path; m.set/get/has/...
//! resolved to undefined and faulted "expected function, got undefined".

use frankenengine_engine::HybridRouter;

fn eval_ok(src: &str) -> String {
    let mut r = HybridRouter::default();
    match r.eval(src) {
        Ok(o) => o.value,
        Err(e) => panic!("expected Ok for {src:?}, got Err: {e:?}"),
    }
}

#[test]
fn map_set_get() {
    assert_eq!(eval_ok("let m=new Map(); m.set('a',1); m.get('a');"), "1");
}

#[test]
fn map_get_missing_undefined() {
    assert_eq!(
        eval_ok("let m=new Map(); typeof m.get('nope');"),
        "undefined"
    );
}

#[test]
fn map_has_and_delete() {
    assert_eq!(
        eval_ok("let m=new Map(); m.set('a',1); m.has('a');"),
        "true"
    );
    assert_eq!(
        eval_ok("let m=new Map(); m.set('a',1); m.delete('a'); m.has('a');"),
        "false"
    );
    assert_eq!(
        eval_ok("let m=new Map(); m.set('a',1); m.delete('a');"),
        "true"
    );
    assert_eq!(eval_ok("let m=new Map(); m.delete('a');"), "false");
}

#[test]
fn map_size() {
    assert_eq!(
        eval_ok("let m=new Map(); m.set('a',1); m.set('b',2); m.size;"),
        "2"
    );
}

#[test]
fn map_overwrite_keeps_size() {
    assert_eq!(
        eval_ok("let m=new Map(); m.set('a',1); m.set('a',2); m.size;"),
        "1"
    );
    assert_eq!(
        eval_ok("let m=new Map(); m.set('a',1); m.set('a',2); m.get('a');"),
        "2"
    );
}

#[test]
fn map_set_returns_map_for_chaining() {
    assert_eq!(
        eval_ok("let m=new Map(); m.set('a',1).set('b',2); m.get('b');"),
        "2"
    );
}

#[test]
fn map_numeric_keys() {
    assert_eq!(
        eval_ok("let m=new Map(); m.set(1,'one'); m.set(2,'two'); m.get(2);"),
        "two"
    );
}

#[test]
fn set_add_has_size() {
    assert_eq!(eval_ok("let s=new Set(); s.add(3); s.has(3);"), "true");
    assert_eq!(eval_ok("let s=new Set(); s.add(3); s.add(4); s.size;"), "2");
    assert_eq!(eval_ok("let s=new Set(); s.add(3); s.add(3); s.size;"), "1");
    assert_eq!(eval_ok("let s=new Set(); s.has(9);"), "false");
}

#[test]
fn set_delete_and_clear() {
    assert_eq!(
        eval_ok("let s=new Set(); s.add(1); s.delete(1); s.has(1);"),
        "false"
    );
    assert_eq!(
        eval_ok("let s=new Set(); s.add(1); s.add(2); s.clear(); s.size;"),
        "0"
    );
}

#[test]
fn map_clear() {
    assert_eq!(
        eval_ok("let m=new Map(); m.set('a',1); m.set('b',2); m.clear(); m.size;"),
        "0"
    );
    assert_eq!(
        eval_ok("let m=new Map(); m.set('a',1); m.clear(); typeof m.get('a');"),
        "undefined"
    );
}

#[test]
fn user_assigned_property_shadows_builtin() {
    // Own data property wins over the builtin method (member-access seam order).
    assert_eq!(eval_ok("let m=new Map(); m.set=42; m.set;"), "42");
}
