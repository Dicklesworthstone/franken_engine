//! Borrow the canonical UTF-8 projection instead of decoding and re-encoding it.
//!
//! JsString's projection already replaces each lone UTF-16 surrogate with
//! U+FFFD, exactly as TextEncoder's USVString input conversion requires. A
//! scalar in this projection consumes the same number of source code units:
//! one for a replacement or BMP scalar, two for a supplementary scalar.

use super::JsString;

/// The longest whole-scalar UTF-8 prefix that fits, and the source UTF-16
/// units it consumes. The returned bytes borrow the existing string storage;
/// no staging vector is allocated. Only the native destination is written.
pub(super) fn encoded_prefix(text: &JsString, byte_limit: usize) -> (&[u8], usize) {
    if byte_limit == 0 {
        // In particular, do not settle a rope for a zero-length destination.
        return (&[], 0);
    }
    let projection = text.as_utf8_projection();
    let mut end = byte_limit.min(projection.len());
    // UTF-8 scalars have at most three continuation bytes. Never emit a
    // partial scalar, including the replacement for a lone surrogate.
    while !projection.is_char_boundary(end) {
        end -= 1;
    }
    let prefix = &projection.as_bytes()[..end];
    let read = if end == projection.len() {
        text.utf16_len()
    } else if text.is_ascii() {
        end
    } else {
        // Count directly in the already valid bytes: one unit for every
        // scalar lead, and one more for a four-byte supplementary scalar.
        prefix.iter().fold(0, |count, &byte| {
            count + usize::from(byte & 0xC0 != 0x80) + usize::from(byte >= 0xF0)
        })
    };
    (prefix, read)
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use super::encoded_prefix;

    // The previous scalar encoder is intentionally independent of both the
    // UTF-8 projection and the new boundary/counting implementation.
    fn scalar_prefix(text: &JsString, limit: usize) -> (Vec<u8>, usize) {
        let mut bytes = Vec::new();
        let mut read = 0;
        for decoded in char::decode_utf16(text.encode_utf16()) {
            let width = decoded.as_ref().map_or(1, |ch| ch.len_utf16());
            let scalar = decoded.unwrap_or(char::REPLACEMENT_CHARACTER);
            let mut buffer = [0; 4];
            let encoded = scalar.encode_utf8(&mut buffer).as_bytes();
            if encoded.len() > limit - bytes.len() {
                break;
            }
            bytes.extend_from_slice(encoded);
            read += width;
        }
        (bytes, read)
    }

    fn compare(text: &JsString, limit: usize) {
        let (expected, units) = scalar_prefix(text, limit);
        let (actual, read) = encoded_prefix(text, limit);
        assert_eq!(actual, expected, "limit={limit}");
        assert_eq!(read, units, "limit={limit}");
        if !actual.is_empty() {
            assert_eq!(actual.as_ptr(), text.as_utf8_projection().as_ptr());
        }
    }

    #[test]
    fn every_single_utf16_unit_matches_the_scalar_encoder() {
        for unit in 0..=u16::MAX {
            let text = JsString::from_code_units(&[unit]);
            for limit in (0..=4).chain(std::iter::once(usize::MAX)) {
                compare(&text, limit);
            }
        }
    }

    #[test]
    fn mixed_pairs_and_lone_halves_preserve_all_destination_boundaries() {
        let alphabet = [
            0, 0x7f, 0x80, 0x7ff, 0x800, 0xd7ff, 0xd800, 0xdbff, 0xdc00, 0xdfff, 0xe000,
            0xffff,
        ];
        for left in alphabet {
            for right in alphabet {
                let text = JsString::from_code_units(&[left, right, 0x61, 0xd83d, 0xde00]);
                for limit in 0..=text.len() + 1 {
                    compare(&text, limit);
                }
                compare(&text, usize::MAX);
            }
        }
    }

    #[test]
    fn seeded_exact_strings_match_at_every_byte_limit() {
        let mut seed = 0x3b7d_9511_u32;
        for length in 0..128 {
            let units = (0..length)
                .map(|_| {
                    seed ^= seed << 13;
                    seed ^= seed >> 17;
                    seed ^= seed << 5;
                    seed as u16
                })
                .collect::<Vec<_>>();
            let text = JsString::from_code_units(&units);
            for limit in 0..=text.len() + 1 {
                compare(&text, limit);
            }
        }
    }

    #[test]
    fn long_ascii_unicode_and_rope_inputs_share_the_original_bytes() {
        let ascii = JsString::from("abcdef".repeat(4096));
        let unicode = JsString::from("aé€😀".repeat(1024));
        let rope = ascii.concat(&unicode);
        assert!(rope.concat_parts().nodes > 0);
        for text in [&ascii, &unicode, &rope] {
            for limit in [0, 1, 2, 3, 4, 1023, 1024, text.len() - 1, usize::MAX] {
                compare(text, limit);
            }
        }
        let (bytes, read) = encoded_prefix(&rope, usize::MAX);
        assert_eq!(bytes.len(), rope.len());
        assert_eq!(read, rope.utf16_len());
    }

    fn core() -> InterpreterCore {
        let mut config = InterpreterConfig::quickjs_defaults();
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
        ]
        .into_iter()
        .collect();
        InterpreterCore::new(config, "direct-text-encoding")
    }

    #[test]
    fn native_encode_uses_the_existing_typed_array_allocation_path() {
        let mut core = core();
        let encoder = core.construct_text_encoder().unwrap();
        let text = JsString::from_code_units(&[0, 0x61, 0xe9, 0xd800, 0xd83d, 0xde00, 0xdc00]);
        let expected = scalar_prefix(&text, usize::MAX).0;
        core.seed_register(0, Value::Str(text)).unwrap();
        let result = core
            .text_codec_method("encode", encoder, RegRange { start: 0, count: 1 })
            .unwrap();
        assert_eq!(core.text_codec_input_bytes(&result).unwrap(), expected);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn native_encode_into_keeps_progress_and_untouched_destination_bytes() {
        let mut core = core();
        let encoder = core.construct_text_encoder().unwrap();
        let text = JsString::from_code_units(&[0x61, 0xe9, 0xd800, 0xd83d, 0xde00, 0x62]);
        for limit in 0..=16 {
            let (expected, read) = scalar_prefix(&text, limit);
            let destination = core
                .alloc_uint8_array_from_bytes(&vec![0xa5; limit])
                .unwrap();
            core.seed_register(0, Value::Str(text.clone())).unwrap();
            core.seed_register(1, Value::Object(destination)).unwrap();
            let Value::Object(result) = core
                .text_codec_method(
                    "encodeInto",
                    encoder.clone(),
                    RegRange { start: 0, count: 2 },
                )
                .unwrap()
            else {
                panic!("encoding progress must be an object");
            };
            assert_eq!(
                core.heap[result.0 as usize].properties.get("read"),
                Some(&Value::Int(read as i64))
            );
            assert_eq!(
                core.heap[result.0 as usize].properties.get("written"),
                Some(&Value::Int(expected.len() as i64))
            );
            let stored = core
                .text_codec_input_bytes(&Value::Object(destination))
                .unwrap();
            assert_eq!(&stored[..expected.len()], expected);
            assert!(stored[expected.len()..].iter().all(|&byte| byte == 0xa5));
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes()
            );
        }
    }

    #[test]
    fn native_encode_still_refuses_an_unadmitted_destination_allocation() {
        let mut core = core();
        let encoder = core.construct_text_encoder().unwrap();
        core.seed_register(0, Value::str("a".repeat(4096)))
            .unwrap();
        core.config.max_total_memory_bytes = core.estimated_memory_bytes();
        assert!(matches!(
            core.text_codec_method("encode", encoder, RegRange { start: 0, count: 1 }),
            Err(InterpreterError::MemoryBudgetExceeded { .. })
        ));
    }
}
