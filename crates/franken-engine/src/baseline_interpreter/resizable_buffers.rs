//! Resizable ArrayBuffers, growable SharedArrayBuffers and ArrayBuffer
//! transfer (ES2024 25.1, 25.2; bd-9vouw.256).
//!
//! A buffer made with `{ maxByteLength }` keeps that maximum and resizes
//! (ArrayBuffer `resize`) or grows (SharedArrayBuffer `grow`) in place up to
//! it. `transfer` and `transferToFixedLength` move the bytes into a new
//! buffer and detach the original, whose byte length reads 0.
//!
//! Views cache their lengths: a typed array's `length`, `byteLength` and
//! `byteOffset` slots and its [`TypedArrayView`] fields, a DataView's
//! likewise. A view over a resizable buffer carries [`ViewBounds`] and is
//! registered on the buffer, and every resize recomputes the registered
//! views. A length-tracking view (made without an explicit length) follows
//! the buffer. A fixed-length one is out of bounds while the buffer ends
//! before it (its lengths and offset read 0, element reads are undefined and
//! writes ignored, its methods throw a TypeError) and comes back when the
//! buffer grows again. Detaching recomputes every view of the buffer,
//! registered or not.
//!
//! Only a buffer's current bytes are allocated, so `maxByteLength` is
//! bounded by what Node accepts on this host, and a resize past the
//! per-buffer cap (`MAX_ARRAY_BUFFER_BYTE_LENGTH`) is a RangeError, as an
//! allocation past it is.

use super::*;

/// The largest `maxByteLength` accepted: Node v22.2.0 accepts 2^45 and
/// refuses 2^46 ("Array buffer allocation failed") on this host.
const MAX_RESIZABLE_BYTE_LENGTH: u64 = 1 << 45;

/// The `ArrayBuffer.prototype` methods served by
/// [`BuiltinFunctionKind::ArrayBufferMethod`].
pub(super) const ARRAY_BUFFER_METHODS: [&str; 3] = ["resize", "transfer", "transferToFixedLength"];

/// Recompute one view's cached lengths over its buffer's `buffer_len` bytes.
/// False when `object` is not a view of `buffer` (a collected one).
fn refresh_view_object(
    object: &mut HeapObject,
    buffer: ObjectId,
    buffer_len: usize,
    detached: bool,
) -> bool {
    let (byte_offset, element_size, bounds) = if let Some(view) = object
        .typed_array
        .as_mut()
        .filter(|view| view.buffer == buffer)
    {
        // A view that registered none (over a fixed-length buffer being
        // detached) keeps its length as [[ArrayLength]].
        let bounds = *view.bounds.get_or_insert(ViewBounds {
            fixed_length: Some(view.length),
            out_of_bounds: false,
        });
        (view.byte_offset, view.kind.element_size(), bounds)
    } else if let Some(view) = object
        .data_view
        .as_mut()
        .filter(|view| view.buffer == buffer)
    {
        let bounds = *view.bounds.get_or_insert(ViewBounds {
            fixed_length: Some(view.byte_length),
            out_of_bounds: false,
        });
        (view.byte_offset, 1, bounds)
    } else {
        return false;
    };
    let current = bounds.current_length(byte_offset, element_size, buffer_len, detached);
    let length = current.unwrap_or(0);
    let bounds = Some(ViewBounds {
        out_of_bounds: current.is_none(),
        ..bounds
    });
    // ES2024 23.2.3.3-5: an out-of-bounds view reads 0 for all three.
    let offset_slot = if current.is_some() { byte_offset } else { 0 };
    let int = |value: usize| Value::Int(i64::try_from(value).unwrap_or(i64::MAX));
    if let Some(view) = object.typed_array.as_mut() {
        view.length = length;
        view.byte_length = length * element_size;
        view.bounds = bounds;
        object.properties.insert("length".to_string(), int(length));
    } else if let Some(view) = object.data_view.as_mut() {
        view.byte_length = length;
        view.bounds = bounds;
        // ES2024 25.3.4.2-3: an out-of-bounds DataView's byteLength and
        // byteOffset are TypeErrors, which the prototype getters raise; its
        // slots are dropped so a read reaches them, and come back with the
        // bounds.
        if current.is_none() {
            object.properties.remove("byteLength");
            object.properties.remove("byteOffset");
            return true;
        }
    }
    object
        .properties
        .insert("byteLength".to_string(), int(length * element_size));
    object
        .properties
        .insert("byteOffset".to_string(), int(offset_slot));
    true
}

impl InterpreterCore {
    /// ES2024 25.1.4.1 ArrayBuffer(length, options) and 25.2.3.1
    /// SharedArrayBuffer(length, options), after the NewTarget check: a
    /// `maxByteLength` option makes the buffer resizable (growable).
    pub(super) fn construct_array_buffer(
        &mut self,
        module: Option<&Ir3Module>,
        args: RegRange,
        shared: bool,
    ) -> Result<ObjectId, InterpreterError> {
        let byte_length = self.array_buffer_byte_length_from_args(module, args)?;
        let max_byte_length = self.array_buffer_max_byte_length_option(module, args)?;
        if let Some(max) = max_byte_length
            && byte_length > max
        {
            return Err(InterpreterError::RangeError {
                message: format!("byteLength {byte_length} exceeds maxByteLength {max}"),
            });
        }
        let buffer = self.alloc_buffer_object(byte_length, shared)?;
        if max_byte_length.is_some() {
            self.mutate_heap(|heap| {
                if let Some(backing) = heap
                    .get_mut(buffer.0 as usize)
                    .and_then(|object| object.array_buffer.as_mut())
                {
                    backing.max_byte_length = max_byte_length;
                }
            });
        }
        Ok(buffer)
    }

    /// ES2024 25.1.3.7 GetArrayBufferMaxByteLengthOption(options).
    fn array_buffer_max_byte_length_option(
        &mut self,
        module: Option<&Ir3Module>,
        args: RegRange,
    ) -> Result<Option<usize>, InterpreterError> {
        let Some(options) = self.builtin_arg(args, 1)? else {
            return Ok(None);
        };
        if !options.is_object_like() {
            return Ok(None);
        }
        let key = RuntimePropertyKey::String(JsString::from("maxByteLength"));
        let value = match (module, &options) {
            (Some(module), _) => self.get_v(module, &options, &key)?,
            (None, Value::Object(object_id)) => {
                self.proxy_aware_get_runtime_property(None, *object_id, &key, options.clone(), 0)?
            }
            (None, _) => Value::Undefined,
        };
        if matches!(value, Value::Undefined) {
            return Ok(None);
        }
        let max = self.buffer_byte_index(module, value, "maxByteLength")?;
        if max as u64 > MAX_RESIZABLE_BYTE_LENGTH {
            return Err(InterpreterError::RangeError {
                message: format!("Array buffer allocation failed: maxByteLength {max}"),
            });
        }
        Ok(Some(max))
    }

    /// ES2020 7.1.22 ToIndex of a buffer length argument.
    fn buffer_byte_index(
        &mut self,
        module: Option<&Ir3Module>,
        value: Value,
        what: &str,
    ) -> Result<usize, InterpreterError> {
        let number = self.object_to_number_primitive(module, value)?;
        Self::to_index_value(&number)?
            .and_then(|index| usize::try_from(index).ok())
            .ok_or_else(|| InterpreterError::RangeError {
                message: format!(
                    "invalid {what} {}; it must be an integer from 0 to 2^53 - 1",
                    self.value_to_string(&number)
                ),
            })
    }

    /// The buffer's backing store.
    fn buffer_backing(&self, buffer: ObjectId) -> Result<&ArrayBufferBacking, InterpreterError> {
        self.heap
            .get(buffer.0 as usize)
            .and_then(|object| object.array_buffer.as_ref())
            .ok_or(InterpreterError::ObjectNotFound { id: buffer.0 })
    }

    /// Set the byte length of a resizable (growable) buffer: growth zero
    /// fills, and every registered view's cached lengths follow.
    fn resize_buffer_bytes(
        &mut self,
        buffer: ObjectId,
        new_len: usize,
    ) -> Result<(), InterpreterError> {
        if new_len as u64 > MAX_ARRAY_BUFFER_BYTE_LENGTH {
            return Err(InterpreterError::RangeError {
                message: format!(
                    "Array buffer allocation failed: byteLength {new_len} exceeds the per-buffer cap of {MAX_ARRAY_BUFFER_BYTE_LENGTH} bytes"
                ),
            });
        }
        let object = self
            .heap
            .get(buffer.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: buffer.0 })?;
        let old_len = self.buffer_backing(buffer)?.bytes.len();
        let previous = Self::estimate_heap_object_bytes(object);
        let next = previous
            .saturating_sub(old_len as u64)
            .saturating_add(new_len as u64);
        self.apply_memory_component_delta(previous, next)?;
        self.mutate_heap(|heap| {
            if let Some(object) = heap.get_mut(buffer.0 as usize) {
                if let Some(backing) = object.array_buffer.as_mut() {
                    backing.bytes.resize(new_len, 0);
                }
                object.properties.insert(
                    "byteLength".to_string(),
                    Value::Int(i64::try_from(new_len).unwrap_or(i64::MAX)),
                );
            }
        });
        self.refresh_buffer_views(buffer)
    }

    /// ES2024 25.1.3.5 DetachArrayBuffer: the bytes are released, the byte
    /// length reads 0, and every view of the buffer goes out of bounds.
    fn detach_array_buffer(&mut self, buffer: ObjectId) -> Result<(), InterpreterError> {
        let object = self
            .heap
            .get(buffer.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: buffer.0 })?;
        let old_len = self.buffer_backing(buffer)?.bytes.len();
        let previous = Self::estimate_heap_object_bytes(object);
        self.apply_memory_component_delta(previous, previous.saturating_sub(old_len as u64))?;
        self.mutate_heap(|heap| {
            if let Some(object) = heap.get_mut(buffer.0 as usize) {
                if let Some(backing) = object.array_buffer.as_mut() {
                    backing.bytes = Vec::new();
                    backing.detached = true;
                }
                object
                    .properties
                    .insert("byteLength".to_string(), Value::Int(0));
            }
        });
        self.refresh_buffer_views(buffer)
    }

    /// Recompute the cached lengths of `buffer`'s views after it resized or
    /// was detached, and drop collected views from its registry.
    fn refresh_buffer_views(&mut self, buffer: ObjectId) -> Result<(), InterpreterError> {
        let backing = self.buffer_backing(buffer)?;
        let (buffer_len, detached) = (backing.bytes.len(), backing.detached);
        let registered = backing.max_byte_length.is_some();
        let candidates: Vec<ObjectId> = if registered {
            backing.views.clone()
        } else {
            // A fixed-length buffer registers no views; only detaching one
            // gets here, so the heap walk is rare.
            self.heap
                .iter_live()
                .filter(|(_, object)| {
                    object
                        .typed_array
                        .as_ref()
                        .is_some_and(|view| view.buffer == buffer)
                        || object
                            .data_view
                            .as_ref()
                            .is_some_and(|view| view.buffer == buffer)
                })
                .filter_map(|(index, _)| u32::try_from(index).ok().map(ObjectId))
                .collect()
        };
        let mut live = Vec::with_capacity(candidates.len());
        for view_id in candidates {
            // A DataView's dropped or restored slots change its estimate.
            let sizes = self.mutate_heap(|heap| {
                let object = heap.get_mut(view_id.0 as usize)?;
                let before = Self::estimate_heap_object_bytes(object);
                refresh_view_object(object, buffer, buffer_len, detached)
                    .then(|| (before, Self::estimate_heap_object_bytes(object)))
            });
            if let Some((before, after)) = sizes {
                if before != after {
                    self.apply_memory_component_delta(before, after)?;
                }
                live.push(view_id);
            }
        }
        if registered && live.len() != self.buffer_backing(buffer)?.views.len() {
            self.set_buffer_view_registry(buffer, live)?;
        }
        Ok(())
    }

    /// Replace a buffer's registered views, charging the registry's bytes.
    fn set_buffer_view_registry(
        &mut self,
        buffer: ObjectId,
        views: Vec<ObjectId>,
    ) -> Result<(), InterpreterError> {
        let object = self
            .heap
            .get(buffer.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: buffer.0 })?;
        let previous = Self::estimate_heap_object_bytes(object);
        let old_count = self.buffer_backing(buffer)?.views.len();
        let entry = std::mem::size_of::<ObjectId>() as u64;
        let next = previous
            .saturating_sub(old_count as u64 * entry)
            .saturating_add(views.len() as u64 * entry);
        self.apply_memory_component_delta(previous, next)?;
        self.mutate_heap(|heap| {
            if let Some(backing) = heap
                .get_mut(buffer.0 as usize)
                .and_then(|object| object.array_buffer.as_mut())
            {
                backing.views = views;
            }
        });
        Ok(())
    }

    /// A new view over a resizable buffer: record its bounds and register it
    /// on the buffer so resizes refresh it. A view over a fixed-length
    /// buffer is left alone.
    pub(super) fn register_buffer_view(
        &mut self,
        view_id: ObjectId,
        bounds: Option<ViewBounds>,
    ) -> Result<(), InterpreterError> {
        let Some(bounds) = bounds else {
            return Ok(());
        };
        let buffer = self.mutate_heap(|heap| {
            let object = heap.get_mut(view_id.0 as usize)?;
            if let Some(view) = object.typed_array.as_mut() {
                view.bounds = Some(bounds);
                Some(view.buffer)
            } else if let Some(view) = object.data_view.as_mut() {
                view.bounds = Some(bounds);
                Some(view.buffer)
            } else {
                None
            }
        });
        let Some(buffer) = buffer else {
            return Ok(());
        };
        let object = self
            .heap
            .get(buffer.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: buffer.0 })?;
        let previous = Self::estimate_heap_object_bytes(object);
        let entry = std::mem::size_of::<ObjectId>() as u64;
        self.apply_memory_component_delta(previous, previous.saturating_add(entry))?;
        self.mutate_heap(|heap| {
            if let Some(backing) = heap
                .get_mut(buffer.0 as usize)
                .and_then(|object| object.array_buffer.as_mut())
            {
                backing.views.push(view_id);
            }
        });
        Ok(())
    }

    /// The bounds a new view over `buffer` takes: `None` over a fixed-length
    /// buffer, otherwise its fixed length (`None`: length-tracking).
    pub(super) fn new_view_bounds(
        &self,
        buffer: ObjectId,
        fixed_length: Option<usize>,
    ) -> Result<Option<ViewBounds>, InterpreterError> {
        Ok(self
            .buffer_backing(buffer)?
            .max_byte_length
            .map(|_| ViewBounds {
                fixed_length,
                out_of_bounds: false,
            }))
    }

    /// Whether the buffer is resizable (growable) and whether it is detached.
    pub(super) fn buffer_resizability(
        &self,
        buffer: ObjectId,
    ) -> Result<(bool, bool), InterpreterError> {
        let backing = self.buffer_backing(buffer)?;
        Ok((backing.max_byte_length.is_some(), backing.detached))
    }

    /// `ArrayBuffer.prototype.resize`, `transfer` and `transferToFixedLength`
    /// (ES2024 25.1.6.6, 25.1.6.8, 25.1.6.9).
    pub(super) fn array_buffer_method(
        &mut self,
        module: &Ir3Module,
        method: &str,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let buffer = self.plain_buffer_receiver(&receiver, false, method)?;
        let argument = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        if method == "resize" {
            let Some(max) = self.buffer_backing(buffer)?.max_byte_length else {
                return Err(InterpreterError::TypeError {
                    expected: "a resizable ArrayBuffer for ArrayBuffer.prototype.resize"
                        .to_string(),
                    got: "a fixed-length ArrayBuffer".to_string(),
                });
            };
            let new_len = self.buffer_byte_index(Some(module), argument, "newLength")?;
            if self.buffer_backing(buffer)?.detached {
                return Err(InterpreterError::TypeError {
                    expected: "an attached ArrayBuffer for ArrayBuffer.prototype.resize"
                        .to_string(),
                    got: "a detached ArrayBuffer".to_string(),
                });
            }
            if new_len > max {
                return Err(InterpreterError::RangeError {
                    message: format!(
                        "ArrayBuffer.prototype.resize: {new_len} exceeds maxByteLength {max}"
                    ),
                });
            }
            self.resize_buffer_bytes(buffer, new_len)?;
            return Ok(Value::Undefined);
        }

        // ES2024 25.1.3.3 ArrayBufferCopyAndDetach.
        let new_len = if matches!(argument, Value::Undefined) {
            self.buffer_backing(buffer)?.bytes.len()
        } else {
            self.buffer_byte_index(Some(module), argument, "newLength")?
        };
        let backing = self.buffer_backing(buffer)?;
        if backing.detached {
            return Err(InterpreterError::TypeError {
                expected: format!("an attached ArrayBuffer for ArrayBuffer.prototype.{method}"),
                got: "a detached ArrayBuffer".to_string(),
            });
        }
        let max_byte_length = if method == "transfer" {
            backing.max_byte_length
        } else {
            None
        };
        if let Some(max) = max_byte_length
            && new_len > max
        {
            return Err(InterpreterError::RangeError {
                message: format!(
                    "ArrayBuffer.prototype.transfer: {new_len} exceeds maxByteLength {max}"
                ),
            });
        }
        if new_len as u64 > MAX_ARRAY_BUFFER_BYTE_LENGTH {
            return Err(InterpreterError::RangeError {
                message: format!(
                    "Array buffer allocation failed: byteLength {new_len} exceeds the per-buffer cap of {MAX_ARRAY_BUFFER_BYTE_LENGTH} bytes"
                ),
            });
        }
        let copied = backing.bytes[..new_len.min(backing.bytes.len())].to_vec();
        let label = backing.label.clone();
        let created = self.alloc_buffer_object(new_len, false)?;
        self.mutate_heap(|heap| {
            if let Some(backing) = heap
                .get_mut(created.0 as usize)
                .and_then(|object| object.array_buffer.as_mut())
            {
                backing.bytes[..copied.len()].copy_from_slice(&copied);
                backing.max_byte_length = max_byte_length;
            }
        });
        self.join_binary_storage_label(created, &label)?;
        self.detach_array_buffer(buffer)?;
        Ok(Value::Object(created))
    }

    /// ES2024 25.2.5.3 SharedArrayBuffer.prototype.grow(newLength).
    pub(super) fn shared_array_buffer_grow(
        &mut self,
        module: &Ir3Module,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let buffer = self.plain_buffer_receiver(&receiver, true, "grow")?;
        let Some(max) = self.buffer_backing(buffer)?.max_byte_length else {
            return Err(InterpreterError::TypeError {
                expected: "a growable SharedArrayBuffer for SharedArrayBuffer.prototype.grow"
                    .to_string(),
                got: "a fixed-length SharedArrayBuffer".to_string(),
            });
        };
        let argument = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let new_len = self.buffer_byte_index(Some(module), argument, "newLength")?;
        let current = self.buffer_backing(buffer)?.bytes.len();
        if new_len < current || new_len > max {
            return Err(InterpreterError::RangeError {
                message: format!(
                    "SharedArrayBuffer.prototype.grow: {new_len} is outside {current}..={max}"
                ),
            });
        }
        self.resize_buffer_bytes(buffer, new_len)?;
        Ok(Value::Undefined)
    }

    /// ES2024 23.2.4.4 ValidateTypedArray's out-of-bounds step: a TypeError
    /// for a typed array whose buffer shrank below it or was detached.
    pub(super) fn reject_out_of_bounds_typed_array(
        view: &TypedArrayView,
        method: &str,
    ) -> Result<(), InterpreterError> {
        if view.bounds.is_some_and(|bounds| bounds.out_of_bounds) {
            return Err(InterpreterError::TypeError {
                expected: format!("an in-bounds typed array for %TypedArray%.prototype.{method}"),
                got: format!("an out-of-bounds or detached {}", view.kind.type_name()),
            });
        }
        Ok(())
    }

    /// ES2024 25.3.1.3 IsViewOutOfBounds checks in the DataView accessors and
    /// get/set methods.
    pub(super) fn reject_out_of_bounds_data_view(
        view: &DataViewView,
        method: &str,
    ) -> Result<(), InterpreterError> {
        if view.bounds.is_some_and(|bounds| bounds.out_of_bounds) {
            return Err(InterpreterError::TypeError {
                expected: format!("an in-bounds DataView for DataView.prototype.{method}"),
                got: "an out-of-bounds or detached DataView".to_string(),
            });
        }
        Ok(())
    }
}
