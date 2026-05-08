#![no_main]

use std::collections::BTreeMap;

use arbitrary::{Arbitrary, Unstructured};
use frankenengine_engine::deterministic_serde::{
    CanonicalF64, CanonicalValue, decode_value, encode_value,
};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 16 * 1024;
const MAX_DEPTH: usize = 8;
const MAX_SEQUENCE_LEN: usize = 16;
const MAX_BYTES_LEN: usize = 256;
const MAX_STRING_LEN: usize = 256;

struct ArbitraryCanonicalValue(CanonicalValue);

impl<'a> Arbitrary<'a> for ArbitraryCanonicalValue {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        arbitrary_value(u, 0).map(Self)
    }
}

fn arbitrary_value(u: &mut Unstructured<'_>, depth: usize) -> arbitrary::Result<CanonicalValue> {
    let tag = if depth >= MAX_DEPTH {
        u.int_in_range(0_u8..=6)?
    } else {
        u.int_in_range(0_u8..=8)?
    };

    Ok(match tag {
        0 => CanonicalValue::U64(u64::arbitrary(u)?),
        1 => CanonicalValue::I64(i64::arbitrary(u)?),
        2 => CanonicalValue::Bool(bool::arbitrary(u)?),
        3 => CanonicalValue::Bytes(bounded_bytes(u, MAX_BYTES_LEN)?),
        4 => CanonicalValue::String(bounded_string(u, MAX_STRING_LEN)?),
        5 => CanonicalValue::Null,
        6 => CanonicalValue::Float(CanonicalF64::new(f64::arbitrary(u)?)),
        7 => {
            let len = u.int_in_range(0_usize..=MAX_SEQUENCE_LEN.min(u.len()))?;
            let mut items = Vec::with_capacity(len);
            for _ in 0..len {
                items.push(arbitrary_value(u, depth + 1)?);
            }
            CanonicalValue::Array(items)
        }
        _ => {
            let len = u.int_in_range(0_usize..=MAX_SEQUENCE_LEN.min(u.len()))?;
            let mut map = BTreeMap::new();
            for _ in 0..len {
                let key = bounded_string(u, MAX_STRING_LEN)?;
                let value = arbitrary_value(u, depth + 1)?;
                map.insert(key, value);
            }
            CanonicalValue::Map(map)
        }
    })
}

fn bounded_bytes(u: &mut Unstructured<'_>, max_len: usize) -> arbitrary::Result<Vec<u8>> {
    let len = u.int_in_range(0_usize..=max_len.min(u.len()))?;
    Ok(u.bytes(len)?.to_vec())
}

fn bounded_string(u: &mut Unstructured<'_>, max_len: usize) -> arbitrary::Result<String> {
    let bytes = bounded_bytes(u, max_len)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let _ = decode_value(data);

    let mut unstructured = Unstructured::new(data);
    let Ok(ArbitraryCanonicalValue(value)) = ArbitraryCanonicalValue::arbitrary(&mut unstructured)
    else {
        return;
    };

    let encoded = encode_value(&value);
    let decoded = decode_value(&encoded).expect("encoded canonical value should decode");
    assert_eq!(decoded, value);
    assert_eq!(encode_value(&decoded), encoded);
});
