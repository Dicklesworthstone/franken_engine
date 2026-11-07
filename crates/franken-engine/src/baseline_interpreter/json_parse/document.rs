//! Iterative JSON container parsing with an admission-accounted work stack.
//!
//! Heap objects remain unpublished until json_parse_document commits. Frames
//! own only the current container and an unfinished object's key, so neither
//! valid deep input nor a malformed suffix recurses on the Rust stack.

use super::*;

enum Container {
    Array {
        object: ObjectId,
        length: u32,
    },
    Object {
        object: ObjectId,
        key: Option<JsString>,
        key_bytes: u64,
    },
}

impl InterpreterCore {
    pub(super) fn json_parse_document_value(
        &mut self,
        units: &[u16],
        pos: &mut usize,
    ) -> Result<Option<Value>, InterpreterError> {
        let mut frames = Vec::<Container>::new();
        let mut retained = 0_u64;
        let outcome = (|| {
            loop {
                self.json_charge_work()?;
                Self::json_skip_ws(units, pos);
                let Some(&unit) = units.get(*pos) else {
                    return Ok(None);
                };
                let mut value = match unit {
                    0x7B | 0x5B => {
                        *pos += 1;
                        let array = unit == 0x5B;
                        let prototype =
                            self.ensure_builtin_prototype(if array { "Array" } else { "Object" })?;
                        let object = if array {
                            self.alloc_array_with_prototype(Some(prototype))?
                        } else {
                            self.alloc_object_with_prototype(Some(prototype))?
                        };
                        Self::json_skip_ws(units, pos);
                        let end = if array { 0x5D } else { 0x7D };
                        if units.get(*pos) == Some(&end) {
                            *pos += 1;
                            if array {
                                self.json_finalize_array_len(object, 0)?;
                            }
                            Value::Object(object)
                        } else {
                            self.json_grow_parse_frames(&mut frames, &mut retained)?;
                            let frame = if array {
                                Container::Array { object, length: 0 }
                            } else {
                                let Some(key) = Self::json_parse_member_key(units, pos) else {
                                    return Ok(None);
                                };
                                let key_bytes = Self::estimate_js_string_bytes(&key);
                                self.json_reserve_temporary(key_bytes)?;
                                retained += key_bytes;
                                Container::Object {
                                    object,
                                    key: Some(key),
                                    key_bytes,
                                }
                            };
                            frames.push(frame);
                            continue;
                        }
                    }
                    0x22 => {
                        let Some(text) = Self::json_parse_string(units, pos) else {
                            return Ok(None);
                        };
                        Value::str(text)
                    }
                    0x74 if units[*pos..].starts_with(&[0x74, 0x72, 0x75, 0x65]) => {
                        *pos += 4;
                        Value::Bool(true)
                    }
                    0x66 if units[*pos..].starts_with(&[0x66, 0x61, 0x6C, 0x73, 0x65]) => {
                        *pos += 5;
                        Value::Bool(false)
                    }
                    0x6E if units[*pos..].starts_with(&[0x6E, 0x75, 0x6C, 0x6C]) => {
                        *pos += 4;
                        Value::Null
                    }
                    0x2D | 0x30..=0x39 => {
                        let Some(number) = Self::json_parse_number(units, pos) else {
                            return Ok(None);
                        };
                        number
                    }
                    _ => return Ok(None),
                };
                loop {
                    let Some(frame) = frames.last_mut() else {
                        return Ok(Some(value));
                    };
                    // A closing suffix can unwind an arbitrarily deep tree.
                    // Keep it interruptible just like the opening descent.
                    self.json_charge_work()?;
                    let (object, end) = match frame {
                        Container::Array { object, length } => {
                            self.json_store_parsed_property(
                                *object,
                                JsString::from(length.to_string()),
                                value,
                            )?;
                            *length = length.checked_add(1).ok_or_else(|| {
                                InterpreterError::RangeError {
                                    message: "JSON array length exceeds the array-index range"
                                        .to_string(),
                                }
                            })?;
                            (*object, 0x5D)
                        }
                        Container::Object {
                            object,
                            key,
                            key_bytes,
                        } => {
                            let outcome = self.json_store_parsed_property(
                                *object,
                                key.take().expect("unfinished JSON member key"),
                                value,
                            );
                            self.json_release_temporary(*key_bytes);
                            retained -= *key_bytes;
                            *key_bytes = 0;
                            outcome?;
                            (*object, 0x7D)
                        }
                    };
                    Self::json_skip_ws(units, pos);
                    match units.get(*pos) {
                        Some(0x2C) => {
                            *pos += 1;
                            if let Container::Object { key, key_bytes, .. } = frame {
                                let Some(next_key) = Self::json_parse_member_key(units, pos) else {
                                    return Ok(None);
                                };
                                *key_bytes = Self::estimate_js_string_bytes(&next_key);
                                self.json_reserve_temporary(*key_bytes)?;
                                retained += *key_bytes;
                                *key = Some(next_key);
                            }
                            break;
                        }
                        Some(unit) if *unit == end => {
                            *pos += 1;
                            if let Container::Array { length, .. } = frame {
                                self.json_finalize_array_len(object, *length)?;
                            }
                            frames.pop();
                            value = Value::Object(object);
                        }
                        _ => return Ok(None),
                    }
                }
            }
        })();
        drop(frames);
        self.json_release_temporary(retained);
        outcome
    }

    /// Read a required member name and colon. In particular, an object comma
    /// never accepts its closing brace as an empty final member.
    fn json_parse_member_key(units: &[u16], pos: &mut usize) -> Option<JsString> {
        Self::json_skip_ws(units, pos);
        let key = Self::json_parse_string(units, pos)?;
        Self::json_skip_ws(units, pos);
        if units.get(*pos) != Some(&0x3A) {
            return None;
        }
        *pos += 1;
        Some(key)
    }

    fn json_grow_parse_frames(
        &mut self,
        frames: &mut Vec<Container>,
        retained: &mut u64,
    ) -> Result<(), InterpreterError> {
        if frames.len() < frames.capacity() {
            return Ok(());
        }
        let capacity = frames
            .capacity()
            .checked_add(frames.capacity().max(1))
            .ok_or_else(|| self.memory_budget_error(u64::MAX, self.heap_object_count_u32()))?;
        let bytes = capacity
            .checked_mul(std::mem::size_of::<Container>())
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(|| self.memory_budget_error(u64::MAX, self.heap_object_count_u32()))?;
        // Vec growth can temporarily own both buffers. Reserve the whole new
        // capacity before allocation, and retire the old charge afterwards.
        self.json_reserve_temporary(bytes)?;
        *retained += bytes;
        let old_bytes = (frames.capacity() * std::mem::size_of::<Container>()) as u64;
        frames
            .try_reserve_exact(capacity - frames.len())
            .map_err(|_| self.memory_budget_error(u64::MAX, self.heap_object_count_u32()))?;
        let actual_bytes = frames
            .capacity()
            .checked_mul(std::mem::size_of::<Container>())
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(|| self.memory_budget_error(u64::MAX, self.heap_object_count_u32()))?;
        if actual_bytes > bytes {
            self.json_reserve_temporary(actual_bytes - bytes)?;
            *retained += actual_bytes - bytes;
        }
        self.json_release_temporary(old_bytes);
        *retained -= old_bytes;
        Ok(())
    }
}
