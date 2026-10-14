//! WHATWG File API `Blob` (bd-9vouw.226): a global in Node since v18. A blob
//! is an immutable byte sequence with a MIME type. The engine keeps both in
//! the object's `blob` slot, so no guest-visible property holds them (the
//! bd-9vouw.150 lesson); `size` and `type` are accessors on Blob.prototype
//! (prototype_getters), `slice`, `text` and `arrayBuffer` its methods, and
//! its @@toStringTag is "Blob". sqids checks `new Blob([alphabet]).size`
//! against the alphabet's length to refuse multibyte alphabets.
//!
//! Not modeled: `stream()`, `bytes()`, `File`, the `endings: 'native'`
//! option, structured cloning of a blob.

use super::*;

/// The methods of Blob.prototype; a [`BuiltinFunctionKind::BlobMethod`]'s
/// specifier is one of them.
pub(super) const BLOB_METHODS: [&str; 3] = ["slice", "text", "arrayBuffer"];

/// A blob's bytes and its type (already lowercased, File API 4.1 step 3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobData {
    pub bytes: Vec<u8>,
    pub content_type: String,
}

impl BuiltinFunction {
    pub(super) fn blob_method(name: &str) -> Option<Self> {
        BLOB_METHODS.contains(&name).then(|| Self {
            kind: BuiltinFunctionKind::BlobMethod,
            module_specifier: BuiltinModuleSpecifier::from_nonempty(name),
            iterator_handle: None,
            bound_object: None,
        })
    }
}

/// The type a blob keeps (File API 4.1 step 3, 4.3.1 step 4.1): the type
/// lowercased when every code unit is printable ASCII, else "".
fn normalized_blob_type(text: &str) -> String {
    if text.chars().all(|c| matches!(c, '\u{20}'..='\u{7e}')) {
        text.to_ascii_lowercase()
    } else {
        String::new()
    }
}

/// Exact output sizes of `String::from_utf8_lossy`, without allocating that
/// output. Each invalid UTF-8 chunk contributes one replacement character.
fn lossy_text_lengths(bytes: &[u8]) -> (usize, usize) {
    bytes
        .utf8_chunks()
        .fold((0_usize, 0_usize), |(utf8, utf16), chunk| {
            let replacement = usize::from(!chunk.invalid().is_empty());
            (
                utf8.saturating_add(chunk.valid().len())
                    .saturating_add(3 * replacement),
                utf16.saturating_add(chunk.valid().encode_utf16().count())
                    .saturating_add(replacement),
            )
        })
}

impl InterpreterCore {
    /// `new Blob(blobParts, options)` (File API 4.1): each part is a blob's
    /// bytes, a buffer source's viewed bytes, or a string's UTF-8 (a lone
    /// surrogate becomes U+FFFD); anything else is a string by ToString.
    /// The blob's IFC label joins every argument's.
    pub(super) fn construct_blob(
        &mut self,
        module: &Ir3Module,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let parts = self.arg_or_undefined(args, 0)?;
        let mut bytes = Vec::new();
        match parts {
            Value::Undefined => {}
            parts if parts.is_object_like() => {
                for part in self.blob_part_values(module, parts)? {
                    self.append_blob_part(&part, &mut bytes)?;
                }
            }
            other => {
                return Err(InterpreterError::TypeError {
                    expected: "an iterable of blob parts for new Blob".to_string(),
                    got: other.type_name().to_string(),
                });
            }
        }
        let content_type = match self.arg_or_undefined(args, 1)? {
            Value::Undefined | Value::Null => String::new(),
            options if options.is_object_like() => {
                let key = RuntimePropertyKey::String(JsString::from("type"));
                match self.get_v(module, &options, &key)? {
                    Value::Undefined => String::new(),
                    value => normalized_blob_type(&self.value_to_string(&value)),
                }
            }
            other => {
                return Err(InterpreterError::TypeError {
                    expected: "an options object for new Blob".to_string(),
                    got: other.type_name().to_string(),
                });
            }
        };
        let blob = self.alloc_blob(bytes, content_type)?;
        let label = self.join_arg_range_label(args)?;
        self.join_object_mutation_label(blob, &label)?;
        Ok(Value::Object(blob))
    }

    fn append_blob_part(
        &mut self,
        part: &Value,
        bytes: &mut Vec<u8>,
    ) -> Result<(), InterpreterError> {
        if let Value::Object(id) = part {
            let object = self
                .heap
                .get(id.0 as usize)
                .ok_or(InterpreterError::ObjectNotFound { id: id.0 })?;
            if let Some(blob) = &object.blob {
                self.check_blob_bytes_headroom(bytes.len(), blob.bytes.len())?;
                bytes.extend_from_slice(&blob.bytes);
                return Ok(());
            }
            if object.array_buffer.is_some()
                || object.typed_array.is_some()
                || object.data_view.is_some()
            {
                let viewed = self.text_codec_input_bytes(part)?;
                self.check_blob_bytes_headroom(bytes.len(), viewed.len())?;
                bytes.extend(viewed);
                return Ok(());
            }
        }
        let text = match part {
            Value::Str(text) => text.clone(),
            other => JsString::from(self.value_to_string(other)),
        };
        // The canonical projection already applies USVString's replacement
        // of lone surrogates. Borrow it instead of allocating a second UTF-8
        // string via a UTF-16 decode/re-encode round trip.
        let utf8 = text.as_utf8_projection().as_bytes();
        self.check_blob_bytes_headroom(bytes.len(), utf8.len())?;
        bytes.extend_from_slice(utf8);
        Ok(())
    }

    /// Refuse to grow a blob under construction past the memory budget
    /// BEFORE copying the next part: the bytes accumulate in a native `Vec`
    /// that `alloc_blob` only charges once every part is in, so repeating one
    /// large blob part could otherwise allocate far past the guest's budget
    /// (`new Blob(Array(1e5).fill(eightMiBBlob))`).
    fn check_blob_bytes_headroom(
        &self,
        accumulated: usize,
        next_part: usize,
    ) -> Result<(), InterpreterError> {
        self.check_temporary_memory_budget(
            u64::try_from(accumulated.saturating_add(next_part)).unwrap_or(u64::MAX),
        )
    }

    /// The blob parts of `parts`, the whole sequence first as WebIDL
    /// converts it. An Array goes through the budget-checked element buffer;
    /// any other iterable (a typed array iterates natively, one `Value` per
    /// byte) is collected with the growing `Vec` charged at each step, so
    /// `new Blob(new Uint8Array(48 << 20))` is refused instead of building
    /// ~1-2 GB of `Value`s before the first part is appended.
    fn blob_part_values(
        &mut self,
        module: &Ir3Module,
        parts: Value,
    ) -> Result<Vec<Value>, InterpreterError> {
        if let Value::Object(array_id) = parts
            && self
                .heap
                .get(array_id.0 as usize)
                .is_some_and(|object| object.is_array)
            && !self.array_from_has_explicit_iterator(array_id)?
        {
            return self.array_like_values(array_id);
        }
        let iterator = self.init_for_of_iterator(Some(module), parts)?;
        let mut values = Vec::new();
        while let Some(value) = self.advance_for_of_iterator(Some(module), iterator.clone())? {
            values.push(value);
            self.check_temporary_memory_budget(
                u64::try_from(values.len().saturating_mul(std::mem::size_of::<Value>()))
                    .unwrap_or(u64::MAX),
            )?;
        }
        Ok(values)
    }

    /// A fresh blob object holding `bytes`, its bytes charged.
    fn alloc_blob(
        &mut self,
        bytes: Vec<u8>,
        content_type: String,
    ) -> Result<ObjectId, InterpreterError> {
        let prototype = self.ensure_builtin_prototype("Blob")?;
        let blob = self.alloc_object_with_prototype(Some(prototype))?;
        let index = blob.0 as usize;
        let mut projected = self
            .heap
            .get(index)
            .ok_or(InterpreterError::ObjectNotFound { id: blob.0 })?
            .clone();
        let previous_bytes = Self::estimate_heap_object_bytes(&projected);
        projected.blob = Some(Box::new(BlobData {
            bytes,
            content_type,
        }));
        let projected_bytes = Self::estimate_heap_object_bytes(&projected);
        self.apply_memory_component_delta(previous_bytes, projected_bytes)?;
        self.mutate_heap(|heap| heap[index] = projected);
        Ok(blob)
    }

    /// The `blob` slot of `value`, if it is a blob.
    fn blob_data(&self, value: &Value) -> Option<&BlobData> {
        match value {
            Value::Object(id) => self.heap.get(id.0 as usize)?.blob.as_deref(),
            _ => None,
        }
    }

    fn require_blob_data(
        &self,
        value: &Value,
        method: &str,
    ) -> Result<&BlobData, InterpreterError> {
        self.blob_data(value)
            .ok_or_else(|| InterpreterError::TypeError {
                expected: format!("Blob receiver for Blob.prototype.{method}"),
                got: value.type_name().to_string(),
            })
    }

    /// Copy only the requested result, after checking its temporary storage.
    /// The immutable source remains in the heap; a tiny slice must not clone
    /// a potentially much larger blob just to get around a Rust borrow.
    fn copy_blob_range(
        &self,
        receiver: &Value,
        start: usize,
        end: usize,
    ) -> Result<Vec<u8>, InterpreterError> {
        let data = self.require_blob_data(receiver, "slice")?;
        let bytes = data.bytes.get(start..end.max(start)).unwrap_or_default();
        self.check_blob_bytes_headroom(0, bytes.len())?;
        Ok(bytes.to_vec())
    }

    /// File API's UTF-8 decode removes one initial BOM, irrespective of MIME
    /// type. Check both string length and allocation headroom before building
    /// the result, including replacement expansion for malformed input.
    fn decode_blob_text(&self, receiver: &Value) -> Result<String, InterpreterError> {
        let data = self.require_blob_data(receiver, "text")?;
        let bytes = data.bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&data.bytes);
        if let Ok(text) = std::str::from_utf8(bytes) {
            self.check_string_limit(text.encode_utf16().count())?;
            self.check_blob_bytes_headroom(0, text.len())?;
            return Ok(text.to_owned());
        }
        let (utf8_bytes, utf16_units) = lossy_text_lengths(bytes);
        self.check_string_limit(utf16_units)?;
        self.check_blob_bytes_headroom(0, utf8_bytes)?;
        Ok(String::from_utf8_lossy(bytes).into_owned())
    }

    /// `get Blob.prototype.size` / `type` on a blob.
    pub(super) fn blob_getter(&self, id: ObjectId, key: &str) -> Option<Value> {
        let blob = self.heap.get(id.0 as usize)?.blob.as_ref()?;
        match key {
            "size" => Some(Value::Int(
                i64::try_from(blob.bytes.len()).unwrap_or(i64::MAX),
            )),
            "type" => Some(Value::str(blob.content_type.clone())),
            _ => None,
        }
    }

    /// Blob.prototype.slice / text / arrayBuffer (File API 4.3). A result
    /// carries the receiver's label, its object label and the arguments'.
    pub(super) fn blob_method(
        &mut self,
        module: &Ir3Module,
        builtin: &BuiltinFunction,
        args: RegRange,
        receiver: Option<Value>,
        receiver_register: Option<u32>,
    ) -> Result<Value, InterpreterError> {
        let method = builtin.display_name();
        let receiver = receiver.unwrap_or(Value::Undefined);
        let len = self.require_blob_data(&receiver, method)?.bytes.len();
        let mut label = self.join_arg_range_label(args)?;
        if let Some(register) = receiver_register {
            label = label.join(self.get_register_label(register)?);
        }
        if let Value::Object(id) = &receiver
            && let Some(object_label) = self.object_mutation_labels.get(id)
        {
            label = label.join(object_label);
        }
        match method {
            "slice" => {
                let start = match self.builtin_number_arg(module, args, 0)? {
                    Some(value) => Self::clamp_relative_index(Self::value_as_integer(&value), len),
                    None => 0,
                };
                let end = match self.builtin_number_arg(module, args, 1)? {
                    Some(value) => Self::clamp_relative_index(Self::value_as_integer(&value), len),
                    None => len,
                };
                let content_type = match self.arg_or_undefined(args, 2)? {
                    Value::Undefined => String::new(),
                    value => normalized_blob_type(&self.value_to_string(&value)),
                };
                // Reborrow only after argument conversion. Builtin callbacks
                // do not arm nested GC while their Rust locals are live (see
                // collector.rs), and guest code cannot mutate a blob's bytes.
                let bytes = self.copy_blob_range(&receiver, start, end)?;
                let blob = self.alloc_blob(bytes, content_type)?;
                self.join_object_mutation_label(blob, &label)?;
                Ok(Value::Object(blob))
            }
            "text" => {
                let text = self.decode_blob_text(&receiver)?;
                let promise = self
                    .create_fulfilled_promise(Self::value_to_js_value(&Value::str(text)), label)?;
                Ok(Value::Promise(promise.0))
            }
            "arrayBuffer" => {
                // Keep this path's existing staging copy: the destination
                // mutation borrows the interpreter mutably. Slicing and text
                // decoding no longer pay for this full-payload clone.
                let data = self.require_blob_data(&receiver, method)?.clone();
                let buffer = self.alloc_array_buffer_object(data.bytes.len())?;
                self.with_array_buffer_bytes_mut(buffer, |backing| {
                    backing[..data.bytes.len()].copy_from_slice(&data.bytes);
                })?;
                let promise = self.create_fulfilled_promise(
                    Self::value_to_js_value(&Value::Object(buffer)),
                    label,
                )?;
                Ok(Value::Promise(promise.0))
            }
            _ => Err(InterpreterError::TypeError {
                expected: "a Blob.prototype method".to_string(),
                got: method.to_string(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn core() -> InterpreterCore {
        let mut config = InterpreterConfig::quickjs_defaults();
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
        ]
        .into_iter()
        .collect();
        InterpreterCore::new(config, "blob-borrowed-reads")
    }

    fn assert_text_lengths(bytes: &[u8]) {
        let expected = String::from_utf8_lossy(bytes);
        assert_eq!(
            lossy_text_lengths(bytes),
            (expected.len(), expected.encode_utf16().count()),
            "bytes={bytes:?}"
        );
    }

    #[test]
    fn replacement_length_scan_matches_all_two_byte_inputs() {
        assert_text_lengths(&[]);
        for first in 0..=u8::MAX {
            assert_text_lengths(&[first]);
            for second in 0..=u8::MAX {
                assert_text_lengths(&[first, second]);
            }
        }
        let mut seed = 0x0b10_b226_u32;
        for length in 0..128 {
            let bytes = (0..length)
                .map(|_| {
                    seed ^= seed << 13;
                    seed ^= seed >> 17;
                    seed ^= seed << 5;
                    seed as u8
                })
                .collect::<Vec<_>>();
            assert_text_lengths(&bytes);
        }
        for bytes in [
            "aé€😀".as_bytes(),
            b"\xf0\x9f\x98\x80\xe2\x82",
            b"\xed\xa0\x80\xf4\x90\x80\x80",
            b"\xef\xbb\xbf\x00\xff",
        ] {
            assert_text_lengths(bytes);
        }
    }

    #[test]
    fn native_text_removes_only_a_leading_utf8_bom() {
        let mut core = core();
        // Expected text was checked against Node v22.16.0 Blob.text().
        let cases: &[(&[u8], &str)] = &[
            (b"", ""),
            (b"\xef\xbb\xbfA", "A"),
            (b"\xef\xbb\xbf\xef\xbb\xbfA", "\u{feff}A"),
            (b"A\xef\xbb\xbf", "A\u{feff}"),
            (b"\xff\xfeA\x00", "\u{fffd}\u{fffd}A\0"),
            (b"\xe2\x82", "\u{fffd}"),
            (b"\xef\xbb", "\u{fffd}"),
            (b"\xff\x00\xf0\x9f\x98\x80", "\u{fffd}\0😀"),
        ];
        for &(bytes, expected) in cases {
            let id = core
                .alloc_blob(bytes.to_vec(), "text/plain;charset=utf-16le".to_string())
                .unwrap();
            let receiver = Value::Object(id);
            assert_eq!(core.decode_blob_text(&receiver).unwrap(), expected);
            assert_eq!(core.blob_data(&receiver).unwrap().bytes, bytes);
        }
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn native_text_checks_utf16_length_and_exact_replacement_headroom() {
        let mut core = core();
        let id = core
            .alloc_blob(b"\xef\xbb\xbf\xf0\x9f\x98\x80\xff".to_vec(), String::new())
            .unwrap();
        let receiver = Value::Object(id);
        core.config.max_string_size = 2;
        assert!(matches!(
            core.decode_blob_text(&receiver),
            Err(InterpreterError::StringLimitExceeded { length: 3, max: 2 })
        ));
        core.config.max_string_size = 3;
        let baseline = core.estimated_memory_bytes();
        core.config.max_total_memory_bytes = baseline + 6;
        assert!(matches!(
            core.decode_blob_text(&receiver),
            Err(InterpreterError::MemoryBudgetExceeded { .. })
        ));
        core.config.max_total_memory_bytes = baseline + 7;
        assert_eq!(core.decode_blob_text(&receiver).unwrap(), "😀\u{fffd}");
        assert_eq!(core.estimated_memory_bytes(), baseline);
    }

    #[test]
    fn tiny_slices_need_only_result_sized_headroom_and_are_independent() {
        let mut core = core();
        let id = core
            .alloc_blob(vec![0x5a; 1 << 20], "application/octet-stream".to_string())
            .unwrap();
        let receiver = Value::Object(id);
        let baseline = core.estimated_memory_bytes();
        core.config.max_total_memory_bytes = baseline + 4;
        for start in [0, 1, 4095, (1 << 20) - 4] {
            let mut result = core.copy_blob_range(&receiver, start, start + 4).unwrap();
            assert_eq!(result, [0x5a; 4]);
            result.fill(0);
            assert_eq!(core.blob_data(&receiver).unwrap().bytes[start], 0x5a);
        }
        core.config.max_total_memory_bytes = baseline;
        assert!(core.copy_blob_range(&receiver, 10, 5).unwrap().is_empty());
        assert!(matches!(
            core.copy_blob_range(&receiver, 0, 1),
            Err(InterpreterError::MemoryBudgetExceeded { .. })
        ));
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn canonical_string_parts_preserve_surrogates_rope_boundaries_and_budget() {
        let mut core = core();
        let high = JsString::from_code_units(&[0xd83d]);
        let low = JsString::from_code_units(&[0xde00]);
        let rope = high.concat(&low);
        let parts = [high, low, rope, JsString::from("aé€\0")];
        let expected = parts
            .iter()
            .map(|text| super::super::text_codec::utf8_of_code_units(text.encode_utf16()))
            .collect::<String>();
        let baseline = core.estimated_memory_bytes();
        core.config.max_total_memory_bytes = baseline + expected.len() as u64;
        let mut bytes = Vec::new();
        for text in parts {
            core.append_blob_part(&Value::Str(text), &mut bytes).unwrap();
        }
        assert_eq!(bytes, expected.as_bytes());
        assert!(matches!(
            core.append_blob_part(&Value::str("x"), &mut bytes),
            Err(InterpreterError::MemoryBudgetExceeded { .. })
        ));
        assert_eq!(bytes, expected.as_bytes());
    }

    #[test]
    fn borrowed_blob_helpers_still_reject_unbranded_receivers() {
        let core = core();
        for receiver in [Value::Undefined, Value::Null, Value::str("not a Blob")] {
            assert!(matches!(
                core.decode_blob_text(&receiver),
                Err(InterpreterError::TypeError { .. })
            ));
            assert!(matches!(
                core.copy_blob_range(&receiver, 0, 0),
                Err(InterpreterError::TypeError { .. })
            ));
        }
    }
}
