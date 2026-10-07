//! WHATWG Encoding: `TextEncoder` and `TextDecoder` (bd-3l74k).
//!
//! Pure builtins with no authority. The encoder produces UTF-8 into a fresh
//! Uint8Array, allocated as `new Uint8Array(n)` is; lone surrogates encode as
//! U+FFFD. The decoder supports utf-8 (with BOM handling and U+FFFD
//! replacement of maximal ill-formed subparts, or a TypeError when `fatal`),
//! utf-16le/be, and windows-1252 (which the `latin1`, `ascii` and `iso-8859-1`
//! labels name). Unsupported labels are a RangeError. Streaming decode retains
//! at most three copied bytes and one BOM decision per decoder. An ordinary
//! decode call flushes the stream; a subsequent call starts a fresh stream.

use super::*;

/// The internal-slot tags of encoder and decoder instances.
pub(super) const TEXT_ENCODER_TYPE: &str = "TextEncoder";
pub(super) const TEXT_DECODER_TYPE: &str = "TextDecoder";

// Fixed-size heap-accounted state, not a side table or a retained input view.
// Guest writes/deletion/redefinition are disabled; native writes use the same
// internal property setter as the other codec slots. This representation does
// not introduce a new object edge for the collector to trace.
const DECODER_STATE_SLOT: &str = "__textDecoderState";

/// The canonical encoding name of a TextDecoder label (WHATWG Encoding 4.2,
/// for the encodings supported here), or `None` when it is unsupported.
fn canonical_decoder_encoding(label: &str) -> Option<&'static str> {
    let label = label
        .trim_matches(|ch: char| matches!(ch, '\t' | '\n' | '\u{c}' | '\r' | ' '))
        .to_ascii_lowercase();
    match label.as_str() {
        "unicode-1-1-utf-8" | "unicode11utf8" | "unicode20utf8" | "utf-8" | "utf8"
        | "x-unicode20utf8" => Some("utf-8"),
        "csunicode" | "iso-10646-ucs-2" | "ucs-2" | "unicode" | "unicodefeff" | "utf-16"
        | "utf-16le" => Some("utf-16le"),
        "unicodefffe" | "utf-16be" => Some("utf-16be"),
        "ansi_x3.4-1968" | "ascii" | "cp1252" | "cp819" | "csisolatin1" | "ibm819"
        | "iso-8859-1" | "iso-ir-100" | "iso8859-1" | "iso88591" | "iso_8859-1"
        | "iso_8859-1:1987" | "l1" | "latin1" | "us-ascii" | "windows-1252" | "x-cp1252" => {
            Some("windows-1252")
        }
        _ => None,
    }
}

/// windows-1252 bytes 0x80..=0x9F (WHATWG index-windows-1252); the rest map
/// to the code point of the same value.
const WINDOWS_1252_HIGH: [u16; 32] = [
    0x20AC, 0x0081, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, 0x02C6, 0x2030, 0x0160, 0x2039,
    0x0152, 0x008D, 0x017D, 0x008F, 0x0090, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014,
    0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0x009D, 0x017E, 0x0178,
];

/// UTF-8 of a string's UTF-16 code units, lone surrogates as U+FFFD.
pub(super) fn utf8_of_code_units(units: impl IntoIterator<Item = u16>) -> String {
    char::decode_utf16(units)
        .map(|unit| unit.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

impl InterpreterCore {
    /// `new TextEncoder()`.
    pub(super) fn construct_text_encoder(&mut self) -> Result<Value, InterpreterError> {
        let prototype = self.ensure_builtin_prototype(TEXT_ENCODER_TYPE)?;
        let encoder = self.alloc_object_with_prototype(Some(prototype))?;
        self.set_object_brand(encoder, TEXT_ENCODER_TYPE)?;
        self.set_object_property(encoder, "encoding".to_string(), Value::str("utf-8"))?;
        self.hide_internal_slots(encoder, &["encoding"])?;
        Ok(Value::Object(encoder))
    }

    /// `new TextDecoder(label = "utf-8", { fatal, ignoreBOM })`.
    pub(super) fn construct_text_decoder(
        &mut self,
        module: Option<&Ir3Module>,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let label = match self.arg_or_undefined(args, 0)? {
            Value::Undefined => "utf-8".to_string(),
            Value::Str(label) => label.to_string(),
            other => self.value_to_string(&other),
        };
        let encoding =
            canonical_decoder_encoding(&label).ok_or_else(|| InterpreterError::RangeError {
                message: format!("The \"{label}\" encoding is not supported"),
            })?;
        let (fatal, ignore_bom) = match self.arg_or_undefined(args, 1)? {
            Value::Object(options) => {
                let fatal = self.proxy_aware_get_property(
                    module,
                    options,
                    "fatal",
                    Value::Object(options),
                    0,
                )?;
                let ignore_bom = self.proxy_aware_get_property(
                    module,
                    options,
                    "ignoreBOM",
                    Value::Object(options),
                    0,
                )?;
                (fatal.is_truthy(), ignore_bom.is_truthy())
            }
            _ => (false, false),
        };
        let prototype = self.ensure_builtin_prototype(TEXT_DECODER_TYPE)?;
        let decoder = self.alloc_object_with_prototype(Some(prototype))?;
        self.set_object_brand(decoder, TEXT_DECODER_TYPE)?;
        self.set_object_property(decoder, "encoding".to_string(), Value::str(encoding))?;
        self.set_object_property(decoder, "fatal".to_string(), Value::Bool(fatal))?;
        self.set_object_property(decoder, "ignoreBOM".to_string(), Value::Bool(ignore_bom))?;
        self.set_object_property(decoder, DECODER_STATE_SLOT.to_string(), Value::Int(0))?;
        self.hide_internal_slots(
            decoder,
            &["encoding", "fatal", "ignoreBOM", DECODER_STATE_SLOT],
        )?;
        self.set_own_property_attributes(
            decoder,
            &RuntimePropertyKey::String(JsString::from(DECODER_STATE_SLOT)),
            PropertyAttributes {
                writable: false,
                enumerable: false,
                configurable: false,
            },
        )?;
        Ok(Value::Object(decoder))
    }

    /// The receiver of a TextEncoder/TextDecoder method, checked by brand.
    fn text_codec_receiver(
        &self,
        receiver: &Value,
        type_name: &str,
        method: &str,
    ) -> Result<ObjectId, InterpreterError> {
        if let Value::Object(object_id) = receiver
            && self
                .heap
                .get(object_id.0 as usize)
                .is_some_and(|object| object.brand() == Some(type_name))
        {
            return Ok(*object_id);
        }
        Err(InterpreterError::TypeError {
            expected: format!("{type_name} receiver for {method}"),
            got: receiver.type_name().to_string(),
        })
    }

    /// TextEncoder.prototype.encode / encodeInto and
    /// TextDecoder.prototype.decode.
    pub(super) fn text_codec_method(
        &mut self,
        method: &str,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        match method {
            "encode" => {
                self.text_codec_receiver(&receiver, TEXT_ENCODER_TYPE, method)?;
                let text = self.text_codec_input_string(args)?;
                let bytes = utf8_of_code_units(text.encode_utf16()).into_bytes();
                Ok(Value::Object(self.alloc_uint8_array_from_bytes(&bytes)?))
            }
            "encodeInto" => {
                self.text_codec_receiver(&receiver, TEXT_ENCODER_TYPE, method)?;
                let text = self.text_codec_input_string(args)?;
                let destination = self.arg_or_undefined(args, 1)?;
                let view = match &destination {
                    Value::Object(object_id) => self
                        .heap
                        .get(object_id.0 as usize)
                        .and_then(|object| object.typed_array.clone())
                        .filter(|view| view.kind == TypedArrayKind::Uint8),
                    _ => None,
                }
                .ok_or_else(|| InterpreterError::TypeError {
                    expected: "Uint8Array destination for TextEncoder.prototype.encodeInto"
                        .to_string(),
                    got: destination.type_name().to_string(),
                })?;
                // Whole characters only: stop before one whose UTF-8 does not
                // fit. `read` counts UTF-16 code units consumed.
                let mut encoded = Vec::new();
                let mut read = 0usize;
                for unit in char::decode_utf16(text.encode_utf16()) {
                    let units_read = unit.as_ref().map_or(1, |ch| ch.len_utf16());
                    let ch = unit.unwrap_or(char::REPLACEMENT_CHARACTER);
                    let mut buffer = [0u8; 4];
                    let utf8 = ch.encode_utf8(&mut buffer).as_bytes();
                    if encoded.len() + utf8.len() > view.byte_length {
                        break;
                    }
                    encoded.extend_from_slice(utf8);
                    read += units_read;
                }
                let written = encoded.len();
                let offset = view.byte_offset;
                self.with_array_buffer_bytes_mut(view.buffer, |bytes| {
                    bytes[offset..offset + written].copy_from_slice(&encoded);
                })?;
                let result = self.alloc_object_with_prototype(None)?;
                self.set_object_property(
                    result,
                    "read".to_string(),
                    Value::Int(i64::try_from(read).unwrap_or(i64::MAX)),
                )?;
                self.set_object_property(
                    result,
                    "written".to_string(),
                    Value::Int(i64::try_from(written).unwrap_or(i64::MAX)),
                )?;
                Ok(Value::Object(result))
            }
            "decode" => {
                let decoder = self.text_codec_receiver(&receiver, TEXT_DECODER_TYPE, method)?;
                let input = self.arg_or_undefined(args, 0)?;
                let stream = match self.arg_or_undefined(args, 1)? {
                    Value::Undefined | Value::Null => false,
                    Value::Object(options) => self
                        .proxy_aware_get_property(
                            None,
                            options,
                            "stream",
                            Value::Object(options),
                            0,
                        )?
                        .is_truthy(),
                    other => {
                        return Err(InterpreterError::TypeError {
                            expected: "an options object for TextDecoder.prototype.decode"
                                .to_string(),
                            got: other.type_name().to_string(),
                        });
                    }
                };
                // Option accessors may reenter decode or mutate the input.
                // Read the current state and copy the view only after them.
                let bytes = self.text_codec_input_bytes(&input)?;
                let slot = |core: &Self, key: &str| {
                    core.heap
                        .get(decoder.0 as usize)
                        .and_then(|object| object.properties.get(key).cloned())
                        .unwrap_or(Value::Undefined)
                };
                let encoding = match slot(self, "encoding") {
                    Value::Str(encoding) => encoding.to_string(),
                    _ => "utf-8".to_string(),
                };
                let fatal = slot(self, "fatal").is_truthy();
                let ignore_bom = slot(self, "ignoreBOM").is_truthy();
                let mut state = match slot(self, DECODER_STATE_SLOT) {
                    Value::Int(packed) => DecodeState::unpack(packed),
                    // Decoders from older heap snapshots have no pending bytes.
                    _ => DecodeState::default(),
                };
                // Incomplete bytes and the BOM decision carry information into
                // later calls. Admit that provenance before publishing state;
                // a public suffix must not declassify a secret prefix.
                if stream || state.streaming {
                    let label = self.join_arg_range_with_object_mutation_label(args)?;
                    self.join_object_mutation_label(decoder, &label)?;
                }
                let decoded = state.decode(&encoding, bytes, fatal, ignore_bom, stream);
                self.set_object_property(
                    decoder,
                    DECODER_STATE_SLOT.to_string(),
                    Value::Int(state.pack()),
                )?;
                let units = decoded.ok_or_else(|| InterpreterError::TypeError {
                    expected: format!("valid {encoding} data"),
                    got: format!("The encoded data was not valid for encoding {encoding}"),
                })?;
                Ok(Value::Str(JsString::from_code_units(&units)))
            }
            _ => Err(InterpreterError::TypeError {
                expected: "TextEncoder or TextDecoder method".to_string(),
                got: method.to_string(),
            }),
        }
    }

    /// The string argument of encode/encodeInto: `undefined` is "".
    fn text_codec_input_string(&self, args: RegRange) -> Result<JsString, InterpreterError> {
        Ok(match self.arg_or_undefined(args, 0)? {
            Value::Undefined => JsString::from(""),
            Value::Str(text) => text,
            other => JsString::from(self.value_to_string(&other)),
        })
    }

    /// The bytes of a decode input: an ArrayBuffer, a typed array or a
    /// DataView (their viewed range). `undefined` is empty.
    pub(super) fn text_codec_input_bytes(
        &self,
        input: &Value,
    ) -> Result<Vec<u8>, InterpreterError> {
        let not_a_buffer = || InterpreterError::TypeError {
            expected: "ArrayBuffer, TypedArray or DataView to decode".to_string(),
            got: input.type_name().to_string(),
        };
        let Value::Object(object_id) = input else {
            return match input {
                Value::Undefined => Ok(Vec::new()),
                _ => Err(not_a_buffer()),
            };
        };
        let object = self
            .heap
            .get(object_id.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
        let (buffer, offset, length) = if let Some(view) = &object.typed_array {
            (view.buffer, view.byte_offset, view.byte_length)
        } else if let Some(view) = &object.data_view {
            (view.buffer, view.byte_offset, view.byte_length)
        } else if object.array_buffer.is_some() {
            let length = self.with_array_buffer_bytes(*object_id, <[u8]>::len)?;
            (*object_id, 0, length)
        } else {
            return Err(not_a_buffer());
        };
        self.with_array_buffer_bytes(buffer, |bytes| {
            bytes
                .get(offset..offset + length)
                .map(<[u8]>::to_vec)
                .unwrap_or_default()
        })
    }

    /// A fresh Uint8Array holding `bytes`, allocated as `new Uint8Array(n)`.
    fn alloc_uint8_array_from_bytes(&mut self, bytes: &[u8]) -> Result<ObjectId, InterpreterError> {
        let view = self.alloc_typed_array_with_fresh_buffer(TypedArrayKind::Uint8, bytes.len())?;
        let buffer = self
            .heap
            .get(view.0 as usize)
            .and_then(|object| object.typed_array.as_ref())
            .map(|typed_array| typed_array.buffer)
            .ok_or_else(|| InterpreterError::TypeError {
                expected: "typed-array view".to_string(),
                got: "ordinary object".to_string(),
            })?;
        self.with_array_buffer_bytes_mut(buffer, |backing| {
            backing[..bytes.len()].copy_from_slice(bytes);
        })?;
        Ok(view)
    }
}

/// A UTF-8 prefix is at most three bytes; UTF-16 can retain one high surrogate
/// and one odd byte. No complete input chunk or previously returned text lives
/// here. The packed state uses only 28 bits and remains a fixed-size heap value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct DecodeState {
    pending: [u8; 3],
    pending_len: usize,
    bom_seen: bool,
    streaming: bool,
}

impl DecodeState {
    fn pack(self) -> i64 {
        i64::from(self.pending[0])
            | (i64::from(self.pending[1]) << 8)
            | (i64::from(self.pending[2]) << 16)
            | ((self.pending_len as i64) << 24)
            | ((self.bom_seen as i64) << 26)
            | ((self.streaming as i64) << 27)
    }

    fn unpack(packed: i64) -> Self {
        Self {
            pending: [packed as u8, (packed >> 8) as u8, (packed >> 16) as u8],
            pending_len: ((packed >> 24) & 3) as usize,
            bom_seen: packed & (1 << 26) != 0,
            streaming: packed & (1 << 27) != 0,
        }
    }

    fn decode(
        &mut self,
        encoding: &str,
        mut bytes: Vec<u8>,
        fatal: bool,
        ignore_bom: bool,
        stream: bool,
    ) -> Option<Vec<u16>> {
        if !self.streaming {
            *self = Self::default();
        }
        if self.pending_len != 0 {
            // Reuse the owned input copy. The only added bytes are the bounded
            // carry; nothing points back into an ArrayBuffer supplied by guest.
            bytes.extend_from_slice(&self.pending[..self.pending_len]);
            bytes.rotate_right(self.pending_len);
        }
        let end = if stream {
            complete_prefix(encoding, &bytes)
        } else {
            bytes.len()
        };
        let decoded = decode_bytes(encoding, &bytes[..end], fatal, ignore_bom || self.bom_seen);
        if decoded.is_none() {
            // Node's decoder is reusable after a fatal decoding failure. Do not
            // retain stale bytes or its prior BOM decision after that failure.
            *self = Self::default();
            return None;
        }
        if !stream {
            // No carry or BOM decision may survive a successful final flush.
            *self = Self::default();
            return decoded;
        }
        self.streaming = true;
        self.bom_seen |= end != 0;
        self.pending = [0; 3];
        self.pending_len = bytes.len() - end;
        debug_assert!(self.pending_len <= self.pending.len());
        self.pending[..self.pending_len].copy_from_slice(&bytes[end..]);
        decoded
    }
}

/// The longest prefix that does not end in an incomplete character. Malformed
/// complete subparts stay in the prefix: streaming must not postpone a fatal
/// error merely because the same chunk also ends with an incomplete character.
fn complete_prefix(encoding: &str, bytes: &[u8]) -> usize {
    match encoding {
        "utf-16le" | "utf-16be" => {
            let mut end = bytes.len() & !1;
            if end >= 2 {
                let pair = [bytes[end - 2], bytes[end - 1]];
                let last = if encoding == "utf-16be" {
                    u16::from_be_bytes(pair)
                } else {
                    u16::from_le_bytes(pair)
                };
                if (0xD800..=0xDBFF).contains(&last) {
                    end -= 2;
                }
            }
            end
        }
        "windows-1252" => bytes.len(),
        _ => {
            let mut offset = 0;
            while let Err(error) = std::str::from_utf8(&bytes[offset..]) {
                offset += error.valid_up_to();
                match error.error_len() {
                    Some(length) => offset += length,
                    None => return offset,
                }
            }
            bytes.len()
        }
    }
}

/// UTF-16 code units of `bytes` decoded as `encoding`, or `None` when `fatal`
/// and the input is invalid. UTF-16 decoding returns scalar values, never
/// unpaired surrogate code units. An unmatched high surrogate plus one trailing
/// byte is a single end-of-queue error (WHATWG shared UTF-16 decoder).
fn decode_bytes(encoding: &str, bytes: &[u8], fatal: bool, ignore_bom: bool) -> Option<Vec<u16>> {
    match encoding {
        "utf-16le" | "utf-16be" => {
            let big_endian = encoding == "utf-16be";
            let read = |offset| {
                let pair = [bytes[offset], bytes[offset + 1]];
                if big_endian {
                    u16::from_be_bytes(pair)
                } else {
                    u16::from_le_bytes(pair)
                }
            };
            let mut units = Vec::new();
            let mut offset = 0;
            while offset < bytes.len() {
                let remaining = bytes.len() - offset;
                if remaining < 2 {
                    if fatal {
                        return None;
                    }
                    units.push(0xFFFD);
                    break;
                }
                let unit = read(offset);
                if offset == 0 && unit == 0xFEFF && !ignore_bom {
                    offset += 2;
                    continue;
                }
                if (0xD800..=0xDBFF).contains(&unit) {
                    if remaining < 4 {
                        if fatal {
                            return None;
                        }
                        units.push(0xFFFD);
                        break;
                    }
                    let low = read(offset + 2);
                    if (0xDC00..=0xDFFF).contains(&low) {
                        units.extend_from_slice(&[unit, low]);
                        offset += 4;
                        continue;
                    }
                    if fatal {
                        return None;
                    }
                    units.push(0xFFFD);
                    // Reprocess the following unit: it may start another pair.
                } else if (0xDC00..=0xDFFF).contains(&unit) {
                    if fatal {
                        return None;
                    }
                    units.push(0xFFFD);
                } else {
                    units.push(unit);
                }
                offset += 2;
            }
            Some(units)
        }
        "windows-1252" => Some(
            bytes
                .iter()
                .map(|&byte| match byte {
                    0x80..=0x9F => WINDOWS_1252_HIGH[usize::from(byte - 0x80)],
                    other => u16::from(other),
                })
                .collect(),
        ),
        _ => {
            let bytes = match bytes {
                [0xEF, 0xBB, 0xBF, rest @ ..] if !ignore_bom => rest,
                _ => bytes,
            };
            let text = if fatal {
                std::str::from_utf8(bytes).ok()?.to_string()
            } else {
                // Maximal ill-formed subparts become U+FFFD, as WHATWG UTF-8
                // decode does.
                String::from_utf8_lossy(bytes).into_owned()
            };
            Some(text.encode_utf16().collect())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_map_to_supported_encodings() {
        assert_eq!(canonical_decoder_encoding(" UTF8 "), Some("utf-8"));
        assert_eq!(canonical_decoder_encoding("latin1"), Some("windows-1252"));
        assert_eq!(canonical_decoder_encoding("utf-16"), Some("utf-16le"));
        assert_eq!(canonical_decoder_encoding("shift_jis"), None);
    }

    #[test]
    fn decoding_follows_the_encoding_standard() {
        let decode = |encoding, bytes: &[u8], fatal, ignore_bom| {
            decode_bytes(encoding, bytes, fatal, ignore_bom)
                .map(|units| String::from_utf16_lossy(&units))
        };
        assert_eq!(
            decode("utf-8", &[0xEF, 0xBB, 0xBF, 0x41], false, false).as_deref(),
            Some("A")
        );
        assert_eq!(
            decode("utf-8", &[0xEF, 0xBB, 0xBF, 0x41], false, true).as_deref(),
            Some("\u{FEFF}A")
        );
        assert_eq!(
            decode("utf-8", &[0xE2, 0x82], false, false).as_deref(),
            Some("\u{FFFD}")
        );
        assert_eq!(decode("utf-8", &[0xFF], true, false), None);
        assert_eq!(
            decode("utf-16le", &[0x41, 0x00, 0x42], false, false).as_deref(),
            Some("A\u{FFFD}")
        );
        assert_eq!(
            decode("windows-1252", &[0xE9, 0x80], false, false).as_deref(),
            Some("\u{E9}\u{20AC}")
        );
    }

    #[test]
    fn lone_surrogates_encode_as_replacement_characters() {
        assert_eq!(
            utf8_of_code_units([0xD800, 0x78]).as_bytes(),
            [0xEF, 0xBF, 0xBD, 0x78]
        );
    }
}

#[cfg(test)]
mod utf16_decoder_tests {
    use super::*;

    #[test]
    fn big_endian_labels_are_canonicalized_without_accepting_unrelated_encodings() {
        for label in ["utf-16be", "\tUTF-16BE\r", "unicodefffe"] {
            assert_eq!(canonical_decoder_encoding(label), Some("utf-16be"));
        }
        assert_eq!(canonical_decoder_encoding("utf-32be"), None);
    }

    #[test]
    fn utf16_invalid_subparts_are_scalar_replacements_in_both_byte_orders() {
        for encoding in ["utf-16le", "utf-16be"] {
            let bytes = |units: &[u16]| {
                units
                    .iter()
                    .flat_map(|unit| {
                        if encoding == "utf-16be" {
                            unit.to_be_bytes()
                        } else {
                            unit.to_le_bytes()
                        }
                    })
                    .collect::<Vec<_>>()
            };
            for (input, expected) in [
                (&[0xD800][..], &[0xFFFD][..]),
                (&[0xDC00][..], &[0xFFFD][..]),
                (&[0xD800, 0x41][..], &[0xFFFD, 0x41][..]),
                (&[0xD800, 0xD801, 0xDC00][..], &[0xFFFD, 0xD801, 0xDC00][..]),
                (&[0xDC00, 0xD800, 0xDC00][..], &[0xFFFD, 0xD800, 0xDC00][..]),
            ] {
                assert_eq!(
                    decode_bytes(encoding, &bytes(input), false, false).as_deref(),
                    Some(expected)
                );
                assert_eq!(decode_bytes(encoding, &bytes(input), true, false), None);
            }
            let mut unmatched = bytes(&[0xD800]);
            unmatched.push(0x41);
            assert_eq!(
                decode_bytes(encoding, &unmatched, false, false),
                Some(vec![0xFFFD])
            );
            assert_eq!(decode_bytes(encoding, &unmatched, true, false), None);
        }
    }

    #[test]
    fn utf16_bom_and_surrogate_pair_are_not_lossily_flattened_by_tests() {
        for (encoding, bytes) in [
            ("utf-16le", [0xFF, 0xFE, 0x3D, 0xD8, 0x00, 0xDE, 0xFF, 0xFE]),
            ("utf-16be", [0xFE, 0xFF, 0xD8, 0x3D, 0xDE, 0x00, 0xFE, 0xFF]),
        ] {
            assert_eq!(
                decode_bytes(encoding, &bytes, true, false),
                Some(vec![0xD83D, 0xDE00, 0xFEFF])
            );
            assert_eq!(
                decode_bytes(encoding, &bytes, true, true),
                Some(vec![0xFEFF, 0xD83D, 0xDE00, 0xFEFF])
            );
        }
    }
}

#[cfg(test)]
mod streaming_decoder_tests {
    use super::*;

    #[test]
    fn packed_state_roundtrips_every_bounded_carry_length() {
        for pending_len in 0..=3 {
            for bom_seen in [false, true] {
                for streaming in [false, true] {
                    let state = DecodeState {
                        pending: [0xEF, 0xBB, 0xBF],
                        pending_len,
                        bom_seen,
                        streaming,
                    };
                    assert_eq!(DecodeState::unpack(state.pack()), state);
                    assert!(state.pack() >= 0 && state.pack() < (1 << 28));
                }
            }
        }
    }

    #[test]
    fn all_two_byte_utf8_streams_equal_one_complete_decode() {
        for first in 0..=u8::MAX {
            for second in 0..=u8::MAX {
                let mut state = DecodeState::default();
                let mut actual = state
                    .decode("utf-8", vec![first], false, false, true)
                    .unwrap();
                actual.extend(
                    state
                        .decode("utf-8", vec![second], false, false, true)
                        .unwrap(),
                );
                actual.extend(state.decode("utf-8", vec![], false, false, false).unwrap());
                let expected: Vec<u16> = String::from_utf8_lossy(&[first, second])
                    .encode_utf16()
                    .collect();
                assert_eq!(actual, expected, "bytes {first:02x} {second:02x}");
                assert_eq!(state.pending_len, 0);
            }
        }
    }

    #[test]
    fn all_single_utf16_units_stream_as_scalars_in_both_byte_orders() {
        for encoding in ["utf-16le", "utf-16be"] {
            for unit in 0..=u16::MAX {
                let bytes = if encoding == "utf-16be" {
                    unit.to_be_bytes()
                } else {
                    unit.to_le_bytes()
                };
                let mut state = DecodeState::default();
                let mut actual = state
                    .decode(encoding, vec![bytes[0]], false, true, true)
                    .unwrap();
                actual.extend(
                    state
                        .decode(encoding, vec![bytes[1]], false, true, true)
                        .unwrap(),
                );
                actual.extend(state.decode(encoding, vec![], false, true, false).unwrap());
                let expected = if (0xD800..=0xDFFF).contains(&unit) {
                    0xFFFD
                } else {
                    unit
                };
                assert_eq!(actual, [expected], "{encoding}: {unit:04x}");
            }
        }
    }

    #[test]
    fn incomplete_utf16_pair_and_odd_byte_share_one_flush_error() {
        let mut state = DecodeState::default();
        assert_eq!(
            state.decode("utf-16le", vec![0, 0xD8, 65], false, false, true),
            Some(vec![])
        );
        assert_eq!(state.pending_len, 3);
        assert_eq!(
            state.decode("utf-16le", vec![], false, false, false),
            Some(vec![0xFFFD])
        );
        assert_eq!(
            state.decode("utf-16le", vec![], false, false, false),
            Some(vec![])
        );
    }

    #[test]
    fn fatal_error_resets_carry_and_bom_state_before_reuse() {
        let mut state = DecodeState::default();
        assert_eq!(
            state.decode("utf-8", vec![0xEF, 0xBB, 0xBF, 0xE2], true, false, true),
            Some(vec![])
        );
        assert!(state.bom_seen);
        assert_eq!(state.decode("utf-8", vec![65], true, false, true), None);
        assert_eq!(state, DecodeState::default());
        assert_eq!(
            state.decode("utf-8", vec![0xEF, 0xBB, 0xBF, 66], true, false, true),
            Some(vec![66])
        );
    }

    #[test]
    fn buffered_input_provenance_remains_on_the_decoder_after_public_suffix_and_flush() {
        let tree = crate::parser_api_stability::parse_script("0;").unwrap();
        let module = crate::lowering_pipeline::lower_ir0_to_ir3(
            &crate::ir_contract::Ir0Module::from_syntax_tree(tree, "decoder-label.js"),
            &crate::lowering_pipeline::LoweringContext::new(
                "decoder-label",
                "carry",
                "builtin-only",
            ),
        )
        .unwrap()
        .ir3;
        let mut core =
            InterpreterCore::new(InterpreterConfig::quickjs_defaults(), "decoder-carry-label");
        let decoder = core
            .construct_text_decoder(None, RegRange { start: 0, count: 0 })
            .unwrap();
        let Value::Object(id) = decoder else {
            panic!("decoder object");
        };
        let prefix = core.alloc_uint8_array_from_bytes(&[0xE2, 0x82]).unwrap();
        let options = core
            .alloc_object_with_properties(&[("stream", Value::Bool(true))])
            .unwrap();
        core.seed_register(0, Value::Object(prefix)).unwrap();
        core.seed_register(1, Value::Object(options)).unwrap();
        core.set_register_label(0, Label::Secret).unwrap();
        assert_eq!(
            core.text_codec_method("decode", decoder.clone(), RegRange { start: 0, count: 2 })
                .unwrap(),
            Value::str("")
        );
        assert_eq!(core.object_mutation_labels.get(&id), Some(&Label::Secret));
        let suffix = core.alloc_uint8_array_from_bytes(&[0xAC]).unwrap();
        core.seed_register(0, Value::Object(suffix)).unwrap();
        core.set_register_label(0, Label::Public).unwrap();
        let method = core
            .get_v(
                &module,
                &decoder,
                &RuntimePropertyKey::String("decode".into()),
            )
            .unwrap();
        let (value, label) = core
            .invoke_inline_method_call_with_argument_label(
                Some(&module),
                method,
                decoder,
                vec![Value::Object(suffix)],
                None,
            )
            .unwrap();
        assert_eq!(value, Value::str("€"));
        assert!(
            label >= Label::Secret,
            "a public suffix must preserve the prefix's label"
        );
        assert_eq!(
            core.heap
                .get(id.0 as usize)
                .unwrap()
                .properties
                .get(DECODER_STATE_SLOT),
            Some(&Value::Int(0))
        );
        assert_eq!(core.object_mutation_labels.get(&id), Some(&Label::Secret));
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}
