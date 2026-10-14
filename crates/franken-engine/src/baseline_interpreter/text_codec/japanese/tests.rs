use super::*;
use super::super::{InterpreterConfig, InterpreterCore, Label, RegRange, RuntimeCapability, RuntimePropertyKey, Value};
use sha2::{Digest, Sha256};

fn units(encoding: &str, bytes: &[u8], fatal: bool) -> Option<Vec<u16>> {
    DecodeState::default()
        .decode_slice(encoding, bytes, fatal, false, false)
        .map(|text| text.code_units_vec())
}

#[test]
fn normative_index_content_and_endianness_are_pinned() {
    // Computed from the independently hash-verified WHATWG text files, not by
    // decoding with the implementation under test. The build script refuses
    // any source whose Git blob differs from those independent upstream pins.
    assert_eq!(format!("{:x}", Sha256::digest(INDEXES)),
        "c1212941b5eee7a51c0d4a850949135e135fa5c10f66ab64e9e25825a79cec94");
    assert_eq!(index(0, false), Some('\u{3000}'));
    assert_eq!(index(108, true), Some('\u{02d8}'));
    assert_eq!(index(116, true), Some('\u{ff5e}'));
    assert_eq!(index(11104, false), None);
    assert_eq!(index(7211, true), None);
    assert_eq!(index(usize::MAX, true), None);
}

#[test]
fn every_jis_pointer_routes_through_the_correct_native_decoder() {
    for pointer in 0..11280 {
        let row = pointer / 188;
        let column = pointer % 188;
        let bytes = [
            (row + if row < 31 { 0x81 } else { 0xc1 }) as u8,
            (column + if column < 63 { 0x40 } else { 0x41 }) as u8,
        ];
        let scalar = if (8836..=10715).contains(&pointer) {
            Some(0xe000 + (pointer - 8836) as u16)
        } else if pointer < JIS0208_LENGTH {
            let value = u16::from_le_bytes([INDEXES[pointer * 2], INDEXES[pointer * 2 + 1]]);
            (value != 0xffff).then_some(value)
        } else { None };
        let mut expected = vec![scalar.unwrap_or(0xfffd)];
        if scalar.is_none() && bytes[1].is_ascii() { expected.push(u16::from(bytes[1])); }
        assert_eq!(units("shift_jis", &bytes, false), Some(expected), "pointer={pointer}");
        assert_eq!(units("shift_jis", &bytes, true), scalar.map(|value| vec![value]), "pointer={pointer}");
    }
    for secondary in [false, true] {
        for pointer in 0..94 * 94 {
            let mut bytes = Vec::new();
            if secondary { bytes.push(0x8f); }
            bytes.extend([(pointer / 94 + 0xa1) as u8, (pointer % 94 + 0xa1) as u8]);
            let (base, length) = if secondary { (JIS0208_LENGTH, JIS0212_LENGTH) } else { (0, JIS0208_LENGTH) };
            let scalar = if pointer < length {
                let offset = (base + pointer) * 2;
                let value = u16::from_le_bytes([INDEXES[offset], INDEXES[offset + 1]]);
                (value != 0xffff).then_some(value)
            } else { None };
            assert_eq!(units("euc-jp", &bytes, false), Some(vec![scalar.unwrap_or(0xfffd)]));
            assert_eq!(units("euc-jp", &bytes, true), scalar.map(|value| vec![value]));
        }
    }
}

#[test]
fn every_two_byte_split_matches_one_shot_and_packed_state_roundtrips() {
    for encoding in ["shift_jis", "euc-jp"] {
        for first in 0..=u8::MAX {
            for second in 0..=u8::MAX {
                let mut state = DecodeState::default();
                let mut actual = state.decode_slice(encoding, &[first], false, false, true).unwrap().code_units_vec();
                assert!(state.pending_len <= 2);
                assert!(state.pack() >= 0 && state.pack() < 1 << 28);
                state = DecodeState::unpack(state.pack());
                actual.extend(state.decode_slice(encoding, &[second], false, false, true).unwrap().code_units_vec());
                // Empty streaming input must not flush an unfinished character.
                assert_eq!(state.decode_slice(encoding, &[], false, false, true).unwrap(), JsString::from(""));
                state = DecodeState::unpack(state.pack());
                actual.extend(state.decode_slice(encoding, &[], false, false, false).unwrap().code_units_vec());
                assert_eq!(Some(actual), units(encoding, &[first, second], false), "{encoding}: {first:02x} {second:02x}");
                assert_eq!(state, DecodeState::default());
            }
        }
    }
}

#[test]
fn invalid_multibyte_sequences_do_not_consume_ascii_delimiters() {
    for (encoding, bytes, expected) in [
        ("shift_jis", &[0x81, 0x22][..], &[0xfffd, 0x22][..]),
        ("shift_jis", &[0x82, 0x7f][..], &[0xfffd, 0x7f][..]),
        ("shift_jis", &[0x81, 0xff, 0x82, 0xa0][..], &[0xfffd, 0x3042][..]),
        ("euc-jp", &[0x8e, 0x22][..], &[0xfffd, 0x22][..]),
        ("euc-jp", &[0x8f, 0xa2, 0x22][..], &[0xfffd, 0x22][..]),
        ("euc-jp", &[0x8f, 0x8f, 0xa4, 0xa2][..], &[0xfffd, 0x3042][..]),
        ("euc-jp", &[0x8f, 0xa2][..], &[0xfffd][..]),
    ] {
        assert_eq!(units(encoding, bytes, false).as_deref(), Some(expected));
        assert_eq!(units(encoding, bytes, true), None);
    }
    assert_eq!(units("shift_jis", &[0x80], true), Some(vec![0x80]));
    assert_eq!(units("shift_jis", &[0xa1, 0xdf], true), Some(vec![0xff61, 0xff9f]));
    assert_eq!(units("euc-jp", &[0x8e, 0xa1, 0x8e, 0xdf], true), Some(vec![0xff61, 0xff9f]));
}

#[test]
// Existing engine policy: fatal errors reset the decoder. This does not
// claim WHATWG retention of the unconsumed input queue after a fatal stream.
fn fatal_errors_and_flushes_release_every_incomplete_prefix() {
    for (encoding, prefix) in [
        ("shift_jis", &[0x82][..]), ("euc-jp", &[0x8e][..]),
        ("euc-jp", &[0x8f][..]), ("euc-jp", &[0x8f, 0xa2][..]),
    ] {
        for flush in [false, true] {
            let mut state = DecodeState::default();
            assert_eq!(state.decode_slice(encoding, prefix, true, false, true), Some(JsString::from("")));
            let invalid = if flush { &[][..] } else { &[0x22][..] };
            assert_eq!(state.decode_slice(encoding, invalid, true, false, !flush), None);
            assert_eq!(state, DecodeState::default());
            assert_eq!(state.decode_slice(encoding, b"ok", true, false, false), Some(JsString::from("ok")));
        }
    }
    let mut corrupt = DecodeState { pending: [0xff; 3], pending_len: 3, streaming: true, bom_seen: false };
    assert!(decode(&mut corrupt, Encoding::ShiftJis, b"A", false, true).is_none());
    assert_eq!(corrupt, DecodeState::default());
}

#[test]
fn every_japanese_alias_uses_ascii_only_case_and_whitespace_rules() {
    for (name, labels) in [
        ("shift_jis", &["csshiftjis", "ms932", "ms_kanji", "shift-jis", "shift_jis", "sjis", "windows-31j", "x-sjis"][..]),
        ("euc-jp", &["cseucpkdfmtjapanese", "euc-jp", "x-euc-jp"][..]),
    ] {
        for label in labels {
            assert_eq!(super::super::canonical_decoder_encoding(label), Some(name));
            assert_eq!(super::super::canonical_decoder_encoding(&format!(" \t{}\r\n", label.to_ascii_uppercase())), Some(name));
            assert_eq!(super::super::canonical_decoder_encoding(&format!("\u{a0}{label}")), None);
        }
    }
}

#[test]
fn carried_japanese_bytes_keep_native_provenance_after_public_suffixes() {
    let tree = crate::parser_api_stability::parse_script("0;").unwrap();
    let module = crate::lowering_pipeline::lower_ir0_to_ir3(
        &crate::ir_contract::Ir0Module::from_syntax_tree(tree, "japanese-carry.js"),
        &crate::lowering_pipeline::LoweringContext::new("japanese", "carry", "builtin-only"),
    ).unwrap().ir3;
    for (encoding, prefix, suffix, expected) in [
        ("shift_jis", &[0x82][..], &[0xa0][..], "あ"),
        ("euc-jp", &[0x8f, 0xa2][..], &[0xb7][..], "～"),
    ] {
        for throughput in [false, true] {
            let mut config = if throughput { InterpreterConfig::v8_defaults() } else { InterpreterConfig::quickjs_defaults() };
            config.granted_capabilities = [RuntimeCapability::VmDispatch, RuntimeCapability::HeapAllocate, RuntimeCapability::Builtin].into_iter().collect();
            let mut core = InterpreterCore::new(config, "japanese-carry");
            core.seed_register(0, Value::str(encoding)).unwrap();
            let decoder = core.construct_text_decoder(None, RegRange { start: 0, count: 1 }).unwrap();
            let Value::Object(id) = decoder else { panic!("decoder object"); };
            let prefix = core.alloc_uint8_array_from_bytes(prefix).unwrap();
            let options = core.alloc_object_with_properties(&[("stream", Value::Bool(true))]).unwrap();
            core.seed_register(0, Value::Object(prefix)).unwrap();
            core.seed_register(1, Value::Object(options)).unwrap();
            core.set_register_label(0, Label::Secret).unwrap();
            assert_eq!(core.text_codec_method("decode", decoder.clone(), RegRange { start: 0, count: 2 }).unwrap(), Value::str(""));
            assert_eq!(core.object_mutation_labels.get(&id), Some(&Label::Secret));
            let suffix = core.alloc_uint8_array_from_bytes(suffix).unwrap();
            core.seed_register(0, Value::Object(suffix)).unwrap();
            core.set_register_label(0, Label::Public).unwrap();
            let method = core.get_v(&module, &decoder, &RuntimePropertyKey::String("decode".into())).unwrap();
            let (value, label) = core.invoke_inline_method_call_with_argument_label(Some(&module), method, decoder, vec![Value::Object(suffix)], None).unwrap();
            assert_eq!(value, Value::str(expected));
            assert!(label >= Label::Secret);
            assert_eq!(core.heap[id.0 as usize].properties.get(super::super::DECODER_STATE_SLOT), Some(&Value::Int(0)));
            assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
        }
    }
}
