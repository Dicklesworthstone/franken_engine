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
                for part in self.promise_combinator_iterable_values(Some(module), parts)? {
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
                bytes.extend_from_slice(&blob.bytes);
                return Ok(());
            }
            if object.array_buffer.is_some()
                || object.typed_array.is_some()
                || object.data_view.is_some()
            {
                bytes.extend(self.text_codec_input_bytes(part)?);
                return Ok(());
            }
        }
        let text = match part {
            Value::Str(text) => text.clone(),
            other => JsString::from(self.value_to_string(other)),
        };
        bytes.extend_from_slice(
            super::text_codec::utf8_of_code_units(text.encode_utf16()).as_bytes(),
        );
        Ok(())
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
        projected.blob = Some(BlobData {
            bytes,
            content_type,
        });
        let projected_bytes = Self::estimate_heap_object_bytes(&projected);
        self.apply_memory_component_delta(previous_bytes, projected_bytes)?;
        self.mutate_heap(|heap| heap[index] = projected);
        Ok(blob)
    }

    /// The `blob` slot of `value`, if it is a blob.
    fn blob_data(&self, value: &Value) -> Option<&BlobData> {
        match value {
            Value::Object(id) => self.heap.get(id.0 as usize)?.blob.as_ref(),
            _ => None,
        }
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
        let Some(data) = self.blob_data(&receiver).cloned() else {
            return Err(InterpreterError::TypeError {
                expected: format!("Blob receiver for Blob.prototype.{method}"),
                got: receiver.type_name().to_string(),
            });
        };
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
                let len = data.bytes.len();
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
                let bytes = data
                    .bytes
                    .get(start..end.max(start))
                    .unwrap_or_default()
                    .to_vec();
                let blob = self.alloc_blob(bytes, content_type)?;
                self.join_object_mutation_label(blob, &label)?;
                Ok(Value::Object(blob))
            }
            "text" => {
                let text = String::from_utf8_lossy(&data.bytes).into_owned();
                let promise = self
                    .create_fulfilled_promise(Self::value_to_js_value(&Value::str(text)), label)?;
                Ok(Value::Promise(promise.0))
            }
            "arrayBuffer" => {
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
