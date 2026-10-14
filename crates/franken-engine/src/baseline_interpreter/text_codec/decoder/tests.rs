//! Compare the production string converter to the retained original codec.

use super::super::{DecodeState, complete_prefix, decode_bytes};
use super::*;

fn compare(bytes: &[u8], encoding: &str, fatal: bool, ignore_bom: bool) {
    let actual = decode_string(encoding, bytes, fatal, ignore_bom);
    let expected = decode_bytes(encoding, bytes, fatal, ignore_bom);
    assert_eq!(
        actual.as_ref().map(JsString::code_units_vec),
        expected,
        "{encoding}, fatal={fatal}, ignore_bom={ignore_bom}, bytes={bytes:x?}"
    );
    if let Some(text) = actual {
        assert!(text.is_well_formed());
        assert_eq!(text.utf16_len(), text.as_str().unwrap().encode_utf16().count());
        assert_eq!(text.concat_parts().nodes, 0);
    }
}

#[test]
fn every_two_byte_input_matches_the_original_codec() {
    for encoding in ["utf-8", "utf-16le", "utf-16be", "windows-1252"] {
        for fatal in [false, true] {
            for ignore_bom in [false, true] {
                compare(&[], encoding, fatal, ignore_bom);
                for a in 0..=u8::MAX {
                    compare(&[a], encoding, fatal, ignore_bom);
                    for b in 0..=u8::MAX {
                        compare(&[a, b], encoding, fatal, ignore_bom);
                    }
                }
            }
        }
    }
}

#[test]
fn utf16_pairs_bom_odd_tails_and_reprocessing_match() {
    let alphabet = [
        0, 65, 0xd7ff, 0xd800, 0xdbff, 0xdc00, 0xdfff, 0xe000, 0xfeff, 0xffff,
    ];
    for encoding in ["utf-16le", "utf-16be"] {
        for a in alphabet {
            for b in alphabet {
                for c in alphabet {
                    let bytes: Vec<u8> = [a, b, c]
                        .into_iter()
                        .flat_map(|unit: u16| {
                            if encoding == "utf-16be" {
                                unit.to_be_bytes()
                            } else {
                                unit.to_le_bytes()
                            }
                        })
                        .collect();
                    for end in 0..=bytes.len() {
                        for fatal in [false, true] {
                            for ignore_bom in [false, true] {
                                compare(&bytes[..end], encoding, fatal, ignore_bom);
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn long_valid_and_malformed_payloads_match_without_utf16_output() {
    let mut examples = vec![
        "plain text".repeat(8192).into_bytes(),
        "é日😀\u{feff}".repeat(8192).into_bytes(),
        vec![0xff; 32768],
    ];
    let mut seed = 0x3745_18ab_u32;
    for length in [3, 7, 31, 255, 4097] {
        examples.push(
            (0..length)
                .map(|_| {
                    seed ^= seed << 13;
                    seed ^= seed >> 17;
                    seed ^= seed << 5;
                    seed as u8
                })
                .collect(),
        );
    }
    for bytes in examples {
        for encoding in ["utf-8", "utf-16le", "utf-16be", "windows-1252"] {
            for fatal in [false, true] {
                for ignore_bom in [false, true] {
                    compare(&bytes, encoding, fatal, ignore_bom);
                }
            }
        }
    }
}

// Original state transition plus the old UTF-16 output converter. Do not
// delegate the expected result to the production string converter.
fn reference(
    state: &mut DecodeState,
    encoding: &str,
    mut bytes: Vec<u8>,
    fatal: bool,
    ignore_bom: bool,
    stream: bool,
) -> Option<Vec<u16>> {
    if !state.streaming {
        *state = DecodeState::default();
    }
    if state.pending_len != 0 {
        bytes.extend_from_slice(&state.pending[..state.pending_len]);
        bytes.rotate_right(state.pending_len);
    }
    let end = if stream {
        complete_prefix(encoding, &bytes)
    } else {
        bytes.len()
    };
    let result = decode_bytes(encoding, &bytes[..end], fatal, ignore_bom || state.bom_seen);
    if result.is_none() || !stream {
        *state = DecodeState::default();
        return result;
    }
    state.streaming = true;
    state.bom_seen |= end != 0;
    state.pending = [0; 3];
    state.pending_len = bytes.len() - end;
    state.pending[..state.pending_len].copy_from_slice(&bytes[end..]);
    result
}

#[test]
fn streamed_output_and_state_match_after_each_chunk_and_reset() {
    let inputs = [
        vec![0xef, 0xbb, 0xbf, 65, 0xf0, 0x9f, 0x98, 0x80, 0xe2, 0x82],
        vec![0xff, 0xfe, 0x3d, 0xd8, 0, 0xde, 0, 0xd8, 65],
        vec![0xfe, 0xff, 0xd8, 0x3d, 0xde, 0, 0xd8, 0, 65],
        vec![0xff, 0xc0, 0x80, 0xed, 0xa0, 0x80, 0xf4, 0x90, 0x80, 0x80],
    ];
    for encoding in ["utf-8", "utf-16le", "utf-16be", "windows-1252"] {
        for input in &inputs {
            for split in 0..=input.len() {
                for fatal in [false, true] {
                    for ignore_bom in [false, true] {
                        let mut actual = DecodeState::default();
                        let mut expected = DecodeState::default();
                        let chunks = [
                            (&input[..split], true),
                            (&input[split..], true),
                            (&[][..], false),
                            (&[0xef][..], true),
                            (&[0xbb, 0xbf, 66][..], false),
                            (&[0xff, 0xfe, 65, 0][..], false),
                            (&[][..], false),
                        ];
                        for (bytes, stream) in chunks {
                            let got = actual.decode_string(
                                encoding, bytes.to_vec(), fatal, ignore_bom, stream,
                            );
                            let want = reference(
                                &mut expected, encoding, bytes.to_vec(), fatal, ignore_bom, stream,
                            );
                            assert_eq!(got.as_ref().map(JsString::code_units_vec), want);
                            assert_eq!(actual, expected);
                            assert_eq!(DecodeState::unpack(actual.pack()), actual);
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn result_owns_text_independently_of_input_and_next_decode() {
    for encoding in ["utf-8", "utf-16le", "utf-16be", "windows-1252"] {
        let mut bytes = "abc😀".repeat(1024).into_bytes();
        let mut state = DecodeState::default();
        let text = state
            .decode_string(encoding, bytes.clone(), false, true, false)
            .unwrap();
        let expected = text.code_units_vec();
        bytes.fill(0);
        state
            .decode_string(encoding, bytes, false, true, false)
            .unwrap();
        assert_eq!(text.code_units_vec(), expected);
        assert_eq!(state, DecodeState::default());
    }
}

fn compare_borrowed_call(
    actual: &mut DecodeState,
    expected: &mut DecodeState,
    encoding: &str,
    bytes: &[u8],
    fatal: bool,
    stream: bool,
) {
    let got = actual.decode_slice(encoding, bytes, fatal, false, stream);
    let want = reference(expected, encoding, bytes.to_vec(), fatal, false, stream);
    assert_eq!(got.as_ref().map(JsString::code_units_vec), want);
    assert_eq!(actual, expected);
}

#[test]
fn every_two_byte_utf8_prefix_preserves_bridge_errors_and_state() {
    for fatal in [false, true] {
        for a in 0..=u8::MAX {
            for b in 0..=u8::MAX {
                let mut actual = DecodeState::default();
                let mut expected = DecodeState::default();
                for (bytes, stream) in [
                    (&[a][..], true),
                    (&[b, 65, 0xf0, 0x9f, 0x98, 0x80, 90][..], true),
                    (&[][..], false),
                ] {
                    compare_borrowed_call(&mut actual, &mut expected, "utf-8", bytes, fatal, stream);
                }
            }
        }
    }
}

#[test]
fn borrowed_streams_preserve_original_fatal_reset_and_input_independence() {
    let mut seed = 0x13ab_9287_u32;
    for encoding in ["utf-8", "utf-16le", "utf-16be", "windows-1252"] {
        for fatal in [false, true] {
            for _ in 0..64 {
                let mut actual = DecodeState::default();
                let mut expected = DecodeState::default();
                for index in 0..24 {
                    let mut bytes: Vec<u8> = (0..index * 3)
                        .map(|_| {
                            seed ^= seed << 13;
                            seed ^= seed >> 17;
                            seed ^= seed << 5;
                            seed as u8
                        })
                        .collect();
                    compare_borrowed_call(
                        &mut actual, &mut expected, encoding, &bytes, fatal, index % 5 != 4,
                    );
                    bytes.fill(0);
                }
                compare_borrowed_call(&mut actual, &mut expected, encoding, &[], fatal, false);
            }
        }
    }
}

fn native_core() -> super::super::InterpreterCore {
    use super::super::{InterpreterConfig, InterpreterCore, RuntimeCapability};
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = [
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
    ]
    .into_iter()
    .collect();
    InterpreterCore::new(config, "borrowed-decoder-input")
}

#[test]
fn native_input_reader_borrows_storage_but_snapshot_consumers_still_copy() {
    use super::super::Value;
    let mut core = native_core();
    let payload = b"original UTF-8 bytes";
    let array = core.alloc_uint8_array_from_bytes(payload).unwrap();
    let buffer = core.heap[array.0 as usize].typed_array.as_ref().unwrap().buffer;
    let pointer = core.with_array_buffer_bytes(buffer, |bytes| bytes.as_ptr()).unwrap();
    let input = Value::Object(array);
    core.with_text_codec_input_bytes(&input, |bytes| {
        assert!(std::ptr::eq(bytes.as_ptr(), pointer));
        assert_eq!(bytes, payload);
    }).unwrap();
    let mut state = DecodeState::default();
    let text = core.with_text_codec_input_bytes(&input, |bytes| {
        state.decode_slice("utf-8", bytes, true, false, false)
    }).unwrap().unwrap();
    let snapshot = core.text_codec_input_bytes(&input).unwrap();
    core.with_array_buffer_bytes_mut(buffer, |bytes| bytes.fill(0)).unwrap();
    assert_eq!(snapshot.as_slice(), &payload[..]);
    assert_eq!(text.as_str(), Some("original UTF-8 bytes"));
    assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
}

#[test]
fn invalid_input_is_rejected_before_carry_or_provenance_is_changed() {
    use super::super::{DECODER_STATE_SLOT, InterpreterError, Label, RegRange, Value};
    let mut core = native_core();
    let decoder = core.construct_text_decoder(None, RegRange { start: 0, count: 0 }).unwrap();
    let Value::Object(id) = decoder else { panic!("decoder object"); };
    let prefix = core.alloc_uint8_array_from_bytes(&[0xe2, 0x82]).unwrap();
    let options = core.alloc_object_with_properties(&[("stream", Value::Bool(true))]).unwrap();
    core.seed_register(0, Value::Object(prefix)).unwrap();
    core.seed_register(1, Value::Object(options)).unwrap();
    core.text_codec_method("decode", decoder.clone(), RegRange { start: 0, count: 2 }).unwrap();
    let carry = core.heap[id.0 as usize].properties.get(DECODER_STATE_SLOT).cloned();
    let label = core.object_mutation_labels.get(&id).cloned();
    core.seed_register(0, Value::Bool(true)).unwrap();
    core.set_register_label(0, Label::Secret).unwrap();
    assert!(matches!(
        core.text_codec_method("decode", decoder, RegRange { start: 0, count: 2 }),
        Err(InterpreterError::TypeError { .. })
    ));
    assert_eq!(core.heap[id.0 as usize].properties.get(DECODER_STATE_SLOT).cloned(), carry);
    assert_eq!(core.object_mutation_labels.get(&id).cloned(), label);
    assert!(core.pending_exception.is_none());
    assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
}
