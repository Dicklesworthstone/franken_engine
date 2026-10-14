//! Shared-carrier regressions for packed numeric properties and dictionary fallback.
#![forbid(unsafe_code)]

use frankenengine_core::js_string::JsString;
use frankenengine_core::object_model::OrderedStringMap;

fn dense(values: &[i64]) -> OrderedStringMap<i64> {
    values
        .iter()
        .enumerate()
        .map(|(index, value)| (index.to_string(), *value))
        .collect()
}

#[test]
fn dictionary_history_preserves_equality_wire_bytes_and_own_key_order() {
    let mut packed = dense(&[10, 20, 30, 40]);
    packed.insert("z".into(), 90);
    packed.insert("a".into(), 91);
    let mut dictionary = packed.clone();
    assert_eq!(dictionary.remove("1"), Some(20));
    dictionary.insert("1".into(), 20);
    assert_eq!(packed, dictionary);
    assert_eq!(format!("{packed:?}"), format!("{dictionary:?}"));
    let wire = serde_json::to_string(&packed).unwrap();
    assert_eq!(wire, r#"{"0":10,"1":20,"2":30,"3":40,"z":90,"a":91}"#);
    assert_eq!(serde_json::to_string(&dictionary).unwrap(), wire);
    let restored: OrderedStringMap<i64> = serde_json::from_str(&wire).unwrap();
    assert_eq!(restored, dictionary);
    assert_eq!(
        restored.into_iter().collect::<Vec<_>>(),
        packed.into_iter().collect::<Vec<_>>()
    );
}

#[test]
fn exact_and_non_index_keys_keep_their_existing_order_and_round_trip() {
    let mut map = dense(&[10, 20]);
    for (key, value) in [("01", 30), ("-0", 40), ("4294967295", 50), ("", 60)] {
        map.insert(key.into(), value);
    }
    let high = JsString::from_code_units(&[0xd800]);
    let low = JsString::from_code_units(&[0xdc00]);
    map.insert_exact(high.clone(), 70);
    map.insert_exact(low.clone(), 80);
    map.insert("4294967294".into(), 90);
    assert_eq!(map.len(), 7);
    assert_eq!(map.exact_len(), 9);
    let keys = map.exact_keys();
    assert_eq!(
        keys,
        [
            JsString::from("0"),
            JsString::from("1"),
            JsString::from("4294967294"),
            JsString::from("01"),
            JsString::from("-0"),
            JsString::from("4294967295"),
            JsString::from(""),
            high.clone(),
            low.clone(),
        ]
    );
    assert_eq!(map.get_index(u32::MAX), None);
    assert_eq!(map.get_index(u32::MAX - 1), Some(&90));
    let wire = serde_json::to_string(&map).unwrap();
    let restored: OrderedStringMap<i64> = serde_json::from_str(&wire).unwrap();
    assert_eq!(restored, map);
    assert_eq!(restored.get_exact(&high), Some(&70));
    assert_eq!(restored.get_exact(&low), Some(&80));
}

#[test]
fn dense_splice_matches_vec_for_packed_and_dictionary_forms() {
    for length in 0..9_usize {
        let original: Vec<i64> = (0..length as i64).collect();
        for start in 0..=length {
            for count in 0..=length - start {
                for added in 0..6 {
                    for dictionary in [false, true] {
                        let items: Vec<i64> = (100..100 + added).collect();
                        let mut expected = original.clone();
                        let removed: Vec<_> = expected
                            .splice(start..start + count, items.clone())
                            .collect();
                        let mut map = dense(&original);
                        if dictionary {
                            map.insert("4294967294".into(), -1);
                            map.remove("4294967294");
                        }
                        map.insert("named".into(), 999);
                        assert_eq!(
                            map.splice_dense_index_values(
                                length as u32,
                                start as u32,
                                count as u32,
                                items,
                            ),
                            Ok(removed)
                        );
                        assert_eq!(map.index_values().copied().collect::<Vec<_>>(), expected);
                        assert_eq!(map.get("named"), Some(&999));
                        for (index, value) in expected.iter().enumerate() {
                            assert_eq!(map.get_index(index as u32), Some(value));
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn shift_and_unshift_preserve_numeric_keys_and_return_values() {
    for dictionary in [false, true] {
        let mut map = dense(&[10, 20, 30]);
        if dictionary {
            map.insert("9".into(), 9);
            map.remove("9");
        }
        map.insert("named".into(), 99);
        assert_eq!(map.shift_dense_index_values(3), Some(10));
        assert_eq!(map.unshift_dense_index_values(2, vec![1, 2, 3]), Ok(()));
        assert_eq!(
            map.index_values().copied().collect::<Vec<_>>(),
            [1, 2, 3, 20, 30]
        );
        assert_eq!(
            map.keys().map(String::as_str).collect::<Vec<_>>(),
            ["0", "1", "2", "3", "4", "named"]
        );
        assert_eq!(map.get("named"), Some(&99));
    }
}

#[test]
fn invalid_dense_moves_are_transactional_even_with_sparse_keys() {
    let mut map = dense(&[10, 20, 30]);
    map.remove("1");
    let before = map.clone();
    assert_eq!(map.shift_dense_index_values(2), None);
    assert_eq!(map.unshift_dense_index_values(2, vec![4]), Err(vec![4]));
    assert_eq!(map.splice_dense_index_values(2, 0, 1, vec![4]), Err(vec![4]));
    assert_eq!(map, before);
    let mut map = dense(&[10, 20, 30]);
    let before = map.clone();
    assert_eq!(
        map.splice_dense_index_values(3, u32::MAX, 1, vec![4]),
        Err(vec![4])
    );
    assert_eq!(map.splice_dense_index_values(3, 2, 2, vec![4]), Err(vec![4]));
    assert_eq!(map, before);
}