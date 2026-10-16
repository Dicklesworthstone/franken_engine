//! Retain preserves mixed-key chronology and rebuilds named-key deletion indices.
use frankenengine_core::js_string::JsString;
use frankenengine_core::object_model::{
    JsValue, ObjectHandle, OrderedStringMap, OrdinaryObject, PropertyDescriptor, PropertyKey,
};

#[test]
fn retained_named_indices_survive_delete_reinsert_and_multiple_compactions() {
    let mut map = OrderedStringMap::new();
    let mut expected = Vec::new();
    for i in 0..160 {
        let key = format!("key-{i}");
        map.insert(key.clone(), i);
        expected.push(key);
    }
    for i in 0..45 {
        map.remove(&format!("key-{i}"));
    }
    expected.retain(|key| map.contains_key(key));
    map.retain(|_, value| *value % 3 != 0);
    expected.retain(|key| map.contains_key(key));
    for i in [47, 80, 110, 157] {
        let key = format!("key-{i}");
        assert_eq!(map.remove(&key), Some(i));
        expected.retain(|entry| entry != &key);
        map.insert(key.clone(), i + 1000);
        expected.push(key);
    }
    map.retain(|_, value| *value % 2 == 0);
    expected.retain(|key| map.contains_key(key));
    assert_eq!(map.keys().cloned().collect::<Vec<_>>(), expected);
    assert_eq!(map.len(), expected.len());
    let rebuilt: OrderedStringMap<i32> = map
        .iter()
        .map(|(key, value)| (key.clone(), *value))
        .collect();
    assert_eq!(map, rebuilt);
    let wire = serde_json::to_string(&map).unwrap();
    assert_eq!(map, serde_json::from_str(&wire).unwrap());
    assert_eq!(
        map.clone()
            .into_iter()
            .map(|(key, _)| key)
            .collect::<Vec<_>>(),
        expected
    );
}

#[test]
fn retain_keeps_exact_only_keys_distinct_and_numeric_keys_sorted() {
    let lone = JsString::from_code_units(&[0xd800]);
    let mut map = OrderedStringMap::new();
    map.insert("10".into(), 10);
    map.insert("2".into(), 2);
    map.insert("before".into(), 3);
    map.insert_exact(lone.clone(), 5);
    map.insert("\u{fffd}".into(), 7);
    map.insert("after".into(), 11);
    for i in 0..80 {
        map.insert(format!("extra-{i}"), 100 + i);
    }
    for i in 0..20 {
        map.remove(&format!("extra-{i}"));
    }
    map.retain(|_, value| *value < 100 && *value != 7);
    assert_eq!(
        map.exact_keys(),
        ["2", "10", "before"]
            .map(JsString::from)
            .into_iter()
            .chain([lone.clone(), JsString::from("after")])
            .collect::<Vec<_>>()
    );
    assert_eq!(map.get_exact(&lone), Some(&5));
    assert_eq!(map.get("\u{fffd}"), None);
    map.remove("before");
    map.insert("before".into(), 13);
    assert_eq!(map.exact_keys().last(), Some(&JsString::from("before")));
    let restored: OrderedStringMap<i32> =
        serde_json::from_str(&serde_json::to_string(&map).unwrap()).unwrap();
    assert_eq!(restored, map);
}

#[test]
fn locked_data_property_refuses_accessor_conversion_with_and_without_a_getter() {
    for get in [None, Some(ObjectHandle(1))] {
        let mut object = OrdinaryObject::default();
        let key = PropertyKey::from("x");
        let data = PropertyDescriptor::Data {
            value: JsValue::Int(1),
            writable: true,
            enumerable: true,
            configurable: false,
        };
        assert!(
            object
                .define_own_property(key.clone(), data.clone())
                .unwrap()
        );
        assert!(
            !object
                .define_own_property(
                    key.clone(),
                    PropertyDescriptor::Accessor {
                        get,
                        set: None,
                        enumerable: true,
                        configurable: false
                    }
                )
                .unwrap()
        );
        assert_eq!(object.get_own_property(&key), Some(&data));
    }
}
