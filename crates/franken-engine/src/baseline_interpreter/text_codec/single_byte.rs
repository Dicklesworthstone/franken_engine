//! WHATWG legacy single-byte decoding, using immutable scalar indexes.
//!
//! The existing Windows-1252 converter remains on its original fast path.
//! ISO-8859-8-I shares ISO-8859-8's index but retains its own canonical name.
//! No ICU, host locale, dynamic index parsing, input copy, or new decoder state.
//!
//! Data: https://encoding.spec.whatwg.org/{encodings,indexes}.json
//! indexes.json Git blob: 3874d66edf154953c7a161fbeb2fc272086173e2.
//! Transcription of the single-byte indexes; null is represented by 0xffff.
//! That sentinel is absent from every defined scalar in these indexes.

// Encoding label/index data: Copyright © WHATWG (Apple, Google, Mozilla, Microsoft).
// Incorporated under the BSD 3-Clause License:
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
// 3. Neither the name of the copyright holder nor the names of its contributors
//    may be used to endorse or promote products derived from this software
//    without specific prior written permission.
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

use super::JsString;

const UNDEFINED: u16 = 0xffff;

/// `label` is already ASCII-lowercased and stripped of ASCII whitespace.
pub(super) fn canonical_encoding(label: &str) -> Option<&'static str> {
    match label {
        "866" | "cp866" | "csibm866" | "ibm866" => Some("ibm866"),
        "csisolatin2" | "iso-8859-2" | "iso-ir-101" | "iso8859-2" | "iso88592"
        | "iso_8859-2" | "iso_8859-2:1987" | "l2" | "latin2" => Some("iso-8859-2"),
        "csisolatin3" | "iso-8859-3" | "iso-ir-109" | "iso8859-3" | "iso88593"
        | "iso_8859-3" | "iso_8859-3:1988" | "l3" | "latin3" => Some("iso-8859-3"),
        "csisolatin4" | "iso-8859-4" | "iso-ir-110" | "iso8859-4" | "iso88594"
        | "iso_8859-4" | "iso_8859-4:1988" | "l4" | "latin4" => Some("iso-8859-4"),
        "csisolatincyrillic" | "cyrillic" | "iso-8859-5" | "iso-ir-144" | "iso8859-5"
        | "iso88595" | "iso_8859-5" | "iso_8859-5:1988" => Some("iso-8859-5"),
        "arabic" | "asmo-708" | "csiso88596e" | "csiso88596i" | "csisolatinarabic"
        | "ecma-114" | "iso-8859-6" | "iso-8859-6-e" | "iso-8859-6-i" | "iso-ir-127"
        | "iso8859-6" | "iso88596" | "iso_8859-6" | "iso_8859-6:1987" => Some("iso-8859-6"),
        "csisolatingreek" | "ecma-118" | "elot_928" | "greek" | "greek8" | "iso-8859-7"
        | "iso-ir-126" | "iso8859-7" | "iso88597" | "iso_8859-7" | "iso_8859-7:1987"
        | "sun_eu_greek" => Some("iso-8859-7"),
        "csiso88598e" | "csisolatinhebrew" | "hebrew" | "iso-8859-8" | "iso-8859-8-e"
        | "iso-ir-138" | "iso8859-8" | "iso88598" | "iso_8859-8" | "iso_8859-8:1988"
        | "visual" => Some("iso-8859-8"),
        "csiso88598i" | "iso-8859-8-i" | "logical" => Some("iso-8859-8-i"),
        "csisolatin6" | "iso-8859-10" | "iso-ir-157" | "iso8859-10" | "iso885910" | "l6"
        | "latin6" => Some("iso-8859-10"),
        "iso-8859-13" | "iso8859-13" | "iso885913" => Some("iso-8859-13"),
        "iso-8859-14" | "iso8859-14" | "iso885914" => Some("iso-8859-14"),
        "csisolatin9" | "iso-8859-15" | "iso8859-15" | "iso885915" | "iso_8859-15" | "l9" => {
            Some("iso-8859-15")
        }
        "iso-8859-16" => Some("iso-8859-16"),
        "cskoi8r" | "koi" | "koi8" | "koi8-r" | "koi8_r" => Some("koi8-r"),
        "koi8-ru" | "koi8-u" => Some("koi8-u"),
        "csmacintosh" | "mac" | "macintosh" | "x-mac-roman" => Some("macintosh"),
        "dos-874" | "iso-8859-11" | "iso8859-11" | "iso885911" | "tis-620" | "windows-874" => {
            Some("windows-874")
        }
        "cp1250" | "windows-1250" | "x-cp1250" => Some("windows-1250"),
        "cp1251" | "windows-1251" | "x-cp1251" => Some("windows-1251"),
        "cp1253" | "windows-1253" | "x-cp1253" => Some("windows-1253"),
        "cp1254" | "csisolatin5" | "iso-8859-9" | "iso-ir-148" | "iso8859-9" | "iso88599"
        | "iso_8859-9" | "iso_8859-9:1989" | "l5" | "latin5" | "windows-1254" | "x-cp1254" => {
            Some("windows-1254")
        }
        "cp1255" | "windows-1255" | "x-cp1255" => Some("windows-1255"),
        "cp1256" | "windows-1256" | "x-cp1256" => Some("windows-1256"),
        "cp1257" | "windows-1257" | "x-cp1257" => Some("windows-1257"),
        "cp1258" | "windows-1258" | "x-cp1258" => Some("windows-1258"),
        "x-mac-cyrillic" | "x-mac-ukrainian" => Some("x-mac-cyrillic"),
        _ => None,
    }
}

// Read-only little-endian u16 indexes, in the match order below. Decoding
// uses explicit byte order, not alignment casts or host-endian assumptions.
// The readable normative data is also pinned in the shared test fixture.
static INDEXES: &[u8; 6656] = include_bytes!("single_byte_indexes.bin");

pub(super) fn index(encoding: &str) -> Option<&'static [u8; 256]> {
    let position = match encoding {
        "ibm866" => 0,
        "iso-8859-2" => 1,
        "iso-8859-3" => 2,
        "iso-8859-4" => 3,
        "iso-8859-5" => 4,
        "iso-8859-6" => 5,
        "iso-8859-7" => 6,
        "iso-8859-8" | "iso-8859-8-i" => 7,
        "iso-8859-10" => 8,
        "iso-8859-13" => 9,
        "iso-8859-14" => 10,
        "iso-8859-15" => 11,
        "iso-8859-16" => 12,
        "koi8-r" => 13,
        "koi8-u" => 14,
        "macintosh" => 15,
        "windows-874" => 16,
        "windows-1250" => 17,
        "windows-1251" => 18,
        "windows-1253" => 19,
        "windows-1254" => 20,
        "windows-1255" => 21,
        "windows-1256" => 22,
        "windows-1257" => 23,
        "windows-1258" => 24,
        "x-mac-cyrillic" => 25,
        _ => return None,
    };
    Some(INDEXES[position * 256..(position + 1) * 256].try_into().expect("128 u16 index entries"))
}

fn value(index: &[u8; 256], pointer: usize) -> u16 {
    u16::from_le_bytes([index[pointer * 2], index[pointer * 2 + 1]])
}

/// Every byte is complete, even if it resembles a UTF-8 lead byte. Neither
/// BOM handling nor Unicode normalization applies to these encodings.
pub(super) fn decode(bytes: &[u8], index: &[u8; 256], fatal: bool) -> Option<JsString> {
    if bytes.is_ascii() {
        return Some(JsString::from(std::str::from_utf8(bytes).ok()?));
    }
    let mut text = String::with_capacity(bytes.len());
    for &byte in bytes {
        let scalar = if byte < 0x80 {
            char::from(byte)
        } else {
            let unit = value(index, usize::from(byte - 0x80));
            if unit == UNDEFINED {
                if fatal {
                    return None;
                }
                char::REPLACEMENT_CHARACTER
            } else {
                char::from_u32(u32::from(unit)).expect("WHATWG index contains Unicode scalars")
            }
        };
        text.push(scalar);
    }
    Some(JsString::from(text))
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{DecodeState, canonical_decoder_encoding, complete_prefix, decoder};

    fn fixtures() -> serde_json::Value {
        serde_json::from_str(include_str!("../../../tests/fixtures/text_decoder_single_byte.json"))
            .expect("pinned WHATWG index fixture")
    }

    fn expected_units(entry: &serde_json::Value) -> Vec<u16> {
        (0..128_u16)
            .chain(entry["high"].as_array().unwrap().iter().map(|value| {
                value.as_u64().map_or(0xfffd, |value| value as u16)
            }))
            .collect()
    }

    #[test]
    fn every_normative_label_has_its_canonical_name_and_ascii_whitespace_rules() {
        let fixtures = fixtures();
        let entries = fixtures["encodings"].as_array().unwrap();
        assert_eq!(entries.len(), 28);
        let mut checked = 0;
        for entry in entries {
            let name = entry["name"].as_str().unwrap();
            for label in entry["labels"].as_array().unwrap() {
                let label = label.as_str().unwrap();
                assert_eq!(canonical_decoder_encoding(label), Some(name), "{label}");
                let decorated = format!("\t\n\r\u{c} {} \r\t", label.to_ascii_uppercase());
                assert_eq!(canonical_decoder_encoding(&decorated), Some(name), "{decorated:?}");
                for non_ascii in ['\u{a0}', '\u{feff}', '\u{2003}', '\u{b}'] {
                    assert_eq!(canonical_decoder_encoding(&format!("{non_ascii}{label}")), None);
                    assert_eq!(canonical_decoder_encoding(&format!("{label}{non_ascii}")), None);
                }
                checked += 1;
            }
        }
        assert_eq!(checked, 168);
        for unsupported in ["", "latin-2", "utf-32", "replacement", "x-user-defined", "shift_jis"] {
            assert_eq!(canonical_decoder_encoding(unsupported), None);
        }
    }

    #[test]
    fn every_byte_matches_the_normative_index_in_both_error_modes() {
        let fixtures = fixtures();
        let input: Vec<u8> = (0..=255).collect();
        for entry in fixtures["encodings"].as_array().unwrap() {
            let name = entry["name"].as_str().unwrap();
            let expected = expected_units(entry);
            for ignore_bom in [false, true] {
                let decoded = decoder::decode_string(name, &input, false, ignore_bom).unwrap();
                assert_eq!(decoded.code_units_vec(), expected, "{name}");
                for byte in 0..=255_u8 {
                    let defined = byte < 128 || !entry["high"][usize::from(byte - 128)].is_null();
                    let decoded = decoder::decode_string(name, &[byte], true, ignore_bom);
                    if defined {
                        assert_eq!(decoded.unwrap().code_units_vec(), [expected[usize::from(byte)]], "{name}: {byte}");
                    } else {
                        assert!(decoded.is_none(), "{name}: undefined byte {byte}");
                    }
                }
            }
        }
    }

    #[test]
    fn every_chunk_boundary_is_immediate_and_flush_does_not_emit_a_suffix() {
        let fixtures = fixtures();
        let input: Vec<u8> = (0..=255).collect();
        for entry in fixtures["encodings"].as_array().unwrap() {
            let name = entry["name"].as_str().unwrap();
            let expected = expected_units(entry);
            for split in 0..=input.len() {
                let mut state = DecodeState::default();
                let first = state.decode_slice(name, &input[..split], false, false, true).unwrap();
                assert_eq!(first.code_units_vec(), expected[..split], "{name}: prefix {split}");
                assert_eq!(complete_prefix(name, &input[..split]), split);
                assert_eq!(state.pending_len, 0, "single-byte input cannot leave a UTF-8 carry");
                let second = state.decode_slice(name, &input[split..], false, true, true).unwrap();
                assert_eq!(second.code_units_vec(), expected[split..], "{name}: suffix {split}");
                assert!(state.decode_slice(name, &[], false, false, false).unwrap().is_empty());
                assert_eq!(state, DecodeState::default());
            }
        }
    }

    #[test]
    fn undefined_bytes_fail_before_a_utf8_looking_suffix_and_decoder_can_be_reused() {
        for name in ["iso-8859-3", "iso-8859-6", "windows-1253", "windows-874"] {
            let table = index(name).unwrap();
            let undefined = (0..128).find(|&pointer| value(table, pointer) == UNDEFINED).unwrap() as u8 + 128;
            let mut state = DecodeState::default();
            assert_eq!(state.decode_slice(name, b"ok", true, false, true).unwrap(), JsString::from("ok"));
            assert!(state.decode_slice(name, &[undefined, 0xe2], true, false, true).is_none());
            assert_eq!(state, DecodeState::default());
            assert_eq!(state.decode_slice(name, b"reused", true, false, false).unwrap(), JsString::from("reused"));
            assert_eq!(state, DecodeState::default());
        }
    }

    #[test]
    fn ascii_controls_are_not_codepage_remapped_and_vietnamese_marks_are_not_normalized() {
        let controls = [0, 0x1a, 0x1c, 0x7f];
        let text = decoder::decode_string("ibm866", &controls, true, false).unwrap();
        assert_eq!(text.code_units_vec(), [0, 0x1a, 0x1c, 0x7f]);
        let text = decoder::decode_string("windows-1258", &[b'a', 0xcc], true, false).unwrap();
        assert_eq!(text.code_units_vec(), [0x61, 0x300]);
    }

    #[test]
    fn utf8_bom_bytes_remain_three_legacy_characters() {
        for ignore_bom in [false, true] {
            let text = decoder::decode_string("windows-1251", &[0xef, 0xbb, 0xbf], true, ignore_bom).unwrap();
            assert_eq!(text.code_units_vec(), [0x43f, 0xbb, 0x457]);
        }
        let text = decoder::decode_string("iso-8859-16", &[0xa4, 0xaa, 0xfe], true, false).unwrap();
        assert_eq!(text.code_units_vec(), [0x20ac, 0x218, 0x21b]);
    }

    #[test]
    fn hebrew_logical_and_visual_names_share_a_table_without_reordering_text() {
        assert!(std::ptr::eq(index("iso-8859-8").unwrap(), index("iso-8859-8-i").unwrap()));
        for name in ["iso-8859-8", "iso-8859-8-i"] {
            let text = decoder::decode_string(name, &[0xe0, b'1', 0xe1], true, false).unwrap();
            assert_eq!(text.code_units_vec(), [0x5d0, 0x31, 0x5d1]);
        }
    }
}
