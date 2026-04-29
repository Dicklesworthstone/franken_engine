//! Integration tests for the ES2020 Proxy and Reflect object-model surface.
//!
//! Proxy/Reflect support currently lives in `object_model`, not as raw IR3
//! builtins. These tests exercise the real implementation directly instead of
//! pretending register 0 contains multiple unrelated builtin functions.

#![forbid(unsafe_code)]

use std::fmt::Debug;

use frankenengine_engine::object_model::{
    JsValue, ManagedObject, ObjectError, ObjectHeap, PropertyKey, Reflect,
};

fn key(name: &str) -> PropertyKey {
    PropertyKey::from(name)
}

fn int(value: i64) -> JsValue {
    JsValue::Int(value)
}

fn proxy_error_contains<T: Debug>(result: Result<T, ObjectError>, text: &str) {
    let err = result.expect_err("proxy operation should be deferred to interpreter");
    assert!(
        err.to_string().contains(text),
        "expected error containing {text:?}, got {err}"
    );
}

#[test]
fn proxy_constructor_creates_proxy_object() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_plain();
    let handler = heap.alloc_plain();

    let proxy = heap.alloc_proxy(target, handler);

    let ManagedObject::Proxy(proxy_object) = heap.get(proxy).unwrap() else {
        panic!("proxy allocation should store a proxy object");
    };
    assert_eq!(proxy_object.target().unwrap(), target);
    assert_eq!(proxy_object.handler().unwrap(), handler);
}

#[test]
fn proxy_get_trap_intercepts_property_access() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_plain();
    let handler = heap.alloc_plain();
    Reflect::set(&mut heap, target, key("test"), int(42)).unwrap();
    let proxy = heap.alloc_proxy(target, handler);

    proxy_error_contains(Reflect::get(&heap, proxy, &key("test")), "proxy get trap");
}

#[test]
fn proxy_set_trap_intercepts_property_assignment() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_plain();
    let handler = heap.alloc_plain();
    let proxy = heap.alloc_proxy(target, handler);

    proxy_error_contains(
        Reflect::set(&mut heap, proxy, key("test"), int(99)),
        "proxy set trap",
    );
    assert_eq!(
        Reflect::get(&heap, target, &key("test")).unwrap(),
        JsValue::Undefined
    );
}

#[test]
fn proxy_has_trap_intercepts_in_operator() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_plain();
    let handler = heap.alloc_plain();
    let proxy = heap.alloc_proxy(target, handler);

    proxy_error_contains(Reflect::has(&heap, proxy, &key("test")), "proxy has trap");
}

#[test]
fn proxy_delete_trap_intercepts_delete_operator() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_plain();
    let handler = heap.alloc_plain();
    let proxy = heap.alloc_proxy(target, handler);

    proxy_error_contains(
        Reflect::delete_property(&mut heap, proxy, &key("test")),
        "proxy deleteProperty trap",
    );
}

#[test]
fn proxy_apply_trap_intercepts_function_call() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_callable(None);
    let handler = heap.alloc_plain();
    let proxy = heap.alloc_proxy(target, handler);

    let request = Reflect::apply(&heap, proxy, JsValue::Undefined, vec![int(1), int(2)]).unwrap();

    assert_eq!(request.target, proxy);
    assert_eq!(request.this_arg, JsValue::Undefined);
    assert_eq!(request.arguments, vec![int(1), int(2)]);
}

#[test]
fn proxy_construct_trap_intercepts_new_operator() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_constructor(None);
    let handler = heap.alloc_plain();
    let proxy = heap.alloc_proxy(target, handler);

    let request = Reflect::construct(&heap, proxy, vec![int(1), int(2)], None).unwrap();

    assert_eq!(request.target, proxy);
    assert_eq!(request.new_target, proxy);
    assert_eq!(request.arguments, vec![int(1), int(2)]);
}

#[test]
fn proxy_revocable_revokes_target_and_handler_access() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_plain();
    let handler = heap.alloc_plain();
    let proxy = heap.alloc_proxy(target, handler);

    heap.revoke_proxy(proxy).unwrap();

    let proxy_object = heap.get(proxy).unwrap().as_proxy().unwrap();
    assert!(proxy_object.is_revoked());
    assert_eq!(
        proxy_object.target().unwrap_err(),
        ObjectError::ProxyRevoked
    );
    assert_eq!(
        proxy_object.handler().unwrap_err(),
        ObjectError::ProxyRevoked
    );
}

#[test]
fn reflect_get_provides_default_behavior() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_plain();
    Reflect::set(&mut heap, target, key("test"), int(123)).unwrap();

    assert_eq!(Reflect::get(&heap, target, &key("test")).unwrap(), int(123));
}

#[test]
fn proxy_revoked_rejects_target_handler_access() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_plain();
    let handler = heap.alloc_plain();
    let proxy = heap.alloc_proxy(target, handler);
    heap.revoke_proxy(proxy).unwrap();

    let proxy_object = heap.get(proxy).unwrap().as_proxy().unwrap();
    assert_eq!(
        proxy_object.target().unwrap_err(),
        ObjectError::ProxyRevoked
    );
    assert_eq!(
        proxy_object.handler().unwrap_err(),
        ObjectError::ProxyRevoked
    );
}

#[test]
fn reflect_set_provides_default_behavior() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_plain();

    assert!(Reflect::set(&mut heap, target, key("test"), int(42)).unwrap());
    assert_eq!(Reflect::get(&heap, target, &key("test")).unwrap(), int(42));
}

#[test]
fn reflect_has_detects_existing_properties() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_plain();
    Reflect::set(&mut heap, target, key("test"), int(123)).unwrap();

    assert!(Reflect::has(&heap, target, &key("test")).unwrap());
}

#[test]
fn reflect_has_returns_false_for_nonexistent_properties() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_plain();

    assert!(!Reflect::has(&heap, target, &key("test")).unwrap());
}

#[test]
fn reflect_delete_property_provides_default_behavior() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_plain();
    Reflect::set(&mut heap, target, key("test"), int(1)).unwrap();

    assert!(Reflect::delete_property(&mut heap, target, &key("test")).unwrap());
    assert!(!Reflect::has(&heap, target, &key("test")).unwrap());
}

#[test]
fn reflect_apply_provides_default_behavior() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_callable(None);

    let request = Reflect::apply(&heap, target, JsValue::Null, vec![int(7)]).unwrap();

    assert_eq!(request.target, target);
    assert_eq!(request.this_arg, JsValue::Null);
    assert_eq!(request.arguments, vec![int(7)]);
}

#[test]
fn reflect_construct_provides_default_behavior() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_constructor(None);

    let request = Reflect::construct(&heap, target, vec![int(7)], None).unwrap();

    assert_eq!(request.target, target);
    assert_eq!(request.new_target, target);
    assert_eq!(request.arguments, vec![int(7)]);
}
