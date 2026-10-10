#![forbid(unsafe_code)]

use std::sync::Arc;

use frankenengine_core::js_string::JsString;
use proptest::prelude::*;

fn assert_metadata(value: &JsString, expected: &[u16]) {
    assert_eq!(value.utf16_len(), expected.len());
    assert_eq!(value.encode_utf16().count(), expected.len());
    assert_eq!(
        value.encode_utf16().size_hint(),
        (expected.len(), Some(expected.len()))
    );
    assert_eq!(value.code_units_vec(), expected);
    assert_eq!(value.is_ascii(), expected.iter().all(|&unit| unit <= 0x7f));
    assert_eq!(value.is_ascii(), value.as_utf8_projection().is_ascii());
    assert_eq!(value.clone().code_units_vec(), expected);
}

#[test]
fn every_constructor_populates_the_same_metadata() {
    for text in [
        "",
        "ASCII\0\x7f",
        "é",
        "\u{800}",
        "\u{d7ff}",
        "\u{e000}",
        "😀",
        "a😀é中b",
    ] {
        let units: Vec<u16> = text.encode_utf16().collect();
        let owned = text.to_owned();
        let values = [
            JsString::from(text),
            JsString::from(owned.clone()),
            JsString::from(&owned),
            JsString::from(Arc::<str>::from(text)),
            JsString::from_code_units(&units),
        ];
        for value in &values {
            assert_metadata(value, &units);
            assert_eq!(value, &values[0]);
            assert_eq!(value.cmp(&values[0]), std::cmp::Ordering::Equal);
        }
    }
    for ch in ['\0', '\x7f', '\u{80}', 'é', '中', '😀', '\u{10ffff}'] {
        let mut buffer = [0_u16; 2];
        assert_metadata(&JsString::from(ch), ch.encode_utf16(&mut buffer));
    }
    assert_metadata(&JsString::empty(), &[]);
    assert_metadata(&JsString::default(), &[]);
}

#[test]
fn every_single_code_unit_has_the_right_length_and_ascii_class() {
    for unit in 0..=u16::MAX {
        let value = JsString::from_code_units(&[unit]);
        assert_metadata(&value, &[unit]);
        assert_eq!(value.code_point_at(0), Some(u32::from(unit)));
        assert_eq!(value.code_point_at(1), None);
        assert_eq!(value.code_point_at(usize::MAX), None);
    }
}

#[test]
fn concatenation_metadata_survives_healing_and_empty_operands() {
    let parts: &[&[u16]] = &[
        &[],
        &[0],
        &[0x61],
        &[0xd800],
        &[0xdc00],
        &[0xd83d, 0xde00],
        &[0x61, 0xd83d],
        &[0xde00, 0x62],
        &[0xd800, 0xd83d, 0xde00],
    ];
    for left in parts {
        for right in parts {
            let expected: Vec<u16> = left.iter().chain(right.iter()).copied().collect();
            let actual = JsString::from_code_units(left).concat(&JsString::from_code_units(right));
            assert_metadata(&actual, &expected);
            assert_eq!(actual, JsString::from_code_units(&expected));
        }
    }
}

#[test]
fn iterator_exhaustion_and_adapter_state_match_a_slice() {
    for units in [
        vec![],
        vec![0, 0x61, 0x7f],
        vec![0x61, 0x80, 0xd83d, 0xde00, 0x62],
        vec![0xd800, 0x61, 0xd83d, 0xde00, 0xdc00],
    ] {
        let value = JsString::from_code_units(&units);
        for skip in (0..=units.len() + 1).chain([usize::MAX]) {
            let mut actual = value.encode_utf16();
            let mut expected = units.iter().copied();
            assert_eq!(actual.nth(skip), expected.nth(skip));
            assert_eq!(actual.len(), expected.len());
            assert_eq!(actual.size_hint(), expected.size_hint());
            assert_eq!(actual.clone().count(), expected.clone().count());
            assert_eq!(actual.clone().last(), expected.clone().next_back());
            assert_eq!(
                actual.clone().collect::<Vec<_>>(),
                expected.clone().collect::<Vec<_>>()
            );
            assert_eq!(actual.next(), expected.next());
            assert_eq!(actual.len(), expected.len());
            assert_eq!(actual.nth(usize::MAX), None);
            assert_eq!(actual.next(), None);
            assert_eq!(actual.next(), None);
            assert_eq!(actual.len(), 0);
            assert_eq!(actual.clone().last(), None);
            assert_eq!(
                actual.fold(9_u64, |acc, unit| acc
                    .wrapping_mul(33)
                    .wrapping_add(u64::from(unit))),
                9
            );

            let skipped: Vec<u16> = value.encode_utf16().skip(skip).collect();
            let expected: Vec<u16> = units.iter().copied().skip(skip).collect();
            assert_eq!(skipped, expected);
        }
        let mut actual = value.encode_utf16();
        for (index, &unit) in units.iter().enumerate() {
            assert_eq!(actual.len(), units.len() - index);
            assert_eq!(actual.next(), Some(unit));
        }
        assert_eq!(actual.len(), 0);
        assert_eq!(actual.next(), None);
    }
}

#[test]
fn metadata_does_not_change_wire_debug_or_canonical_values() {
    let ascii = JsString::from("abc");
    assert_eq!(format!("{ascii:?}"), "JsString { utf8: \"abc\", units: None }");
    assert_eq!(serde_json::to_string(&ascii).unwrap(), "\"abc\"");
    for units in [
        vec![],
        vec![0x61],
        vec![0xd800],
        vec![0xd83d, 0xde00],
        vec![0xd800, 0x61],
    ] {
        let value = JsString::from_code_units(&units);
        let json = serde_json::to_string(&value).unwrap();
        let restored: JsString = serde_json::from_str(&json).unwrap();
        assert_metadata(&restored, &units);
        assert_eq!(restored, value);
        assert_eq!(restored.canonical_value(), value.canonical_value());
    }
    let normalized: JsString = serde_json::from_str(r#"{"$wtf16":[55357,56832]}"#).unwrap();
    assert_metadata(&normalized, &[0xd83d, 0xde00]);
    assert!(normalized.is_well_formed());
    assert_eq!(serde_json::to_string(&normalized).unwrap(), "\"😀\"");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn arbitrary_utf16_and_iterator_operations_remain_exact(
        units in prop::collection::vec(any::<u16>(), 0..128),
        skips in prop::collection::vec(prop_oneof![0_usize..160, Just(usize::MAX)], 0..32),
    ) {
        let value = JsString::from_code_units(&units);
        assert_metadata(&value, &units);
        let mut actual = value.encode_utf16();
        let mut expected = units.iter().copied();
        for skip in skips {
            prop_assert_eq!(actual.nth(skip), expected.nth(skip));
            prop_assert_eq!(actual.len(), expected.len());
            prop_assert_eq!(actual.size_hint(), expected.size_hint());
            prop_assert_eq!(actual.clone().count(), expected.clone().count());
            prop_assert_eq!(actual.clone().last(), expected.clone().next_back());
            prop_assert_eq!(actual.clone().collect::<Vec<_>>(), expected.clone().collect::<Vec<_>>());
        }
        prop_assert_eq!(actual.collect::<Vec<_>>(), expected.collect::<Vec<_>>());
    }
}
