//! Side-effect-free selection between element storage and ordinary [[Set]].
//!
//! A true Array can still have accessors, read-only indices, holes or a Proxy
//! prototype. Its mutators must then use the existing generic property engine.
//! Do not validate by invoking getters: selection must not reorder observable
//! operations. In particular, push/pop inspect only their tail, not all of the
//! existing elements, so repeated appends/removals do not acquire an O(n) guard.

use super::*;

impl InterpreterCore {
    pub(super) fn array_mutation_requires_generic(
        &self,
        array: ObjectId,
        kind: BuiltinFunctionKind,
        args: RegRange,
    ) -> Result<bool, InterpreterError> {
        use BuiltinFunctionKind as K;
        if !matches!(
            kind,
            K::ArrayPush | K::ArrayPop | K::ArrayShift | K::ArrayUnshift
                | K::ArrayReverse | K::ArrayFill
        ) {
            return Ok(false);
        }
        let Some(object) = self.heap.get(array.0 as usize) else {
            return Ok(true);
        };
        let Some(length) = mutation_length(object) else {
            return Ok(true);
        };
        // These checks select the spec path, not an early exception: an empty
        // operation may succeed and a refusal may follow earlier visible writes.
        if !object.is_array || object.is_frozen || object.is_non_extensible {
            return Ok(true);
        }
        match kind {
            K::ArrayPush => {
                if args.count == 0 {
                    return Ok(false); // The caller separately guards length.
                }
                if !append_targets_absent(object, length, args.count) {
                    return Ok(true);
                }
                Ok(!self.array_mutation_plain_prototypes(array)?)
            }
            K::ArrayPop => Ok(!pop_can_use_storage(object, length)),
            K::ArrayUnshift if args.count == 0 => Ok(false),
            K::ArrayFill => {
                // A one-element fill must not scan the rest of a large array.
                // Only already-primitive numeric bounds are inspected here;
                // other conversions stay on the ordinary, observable path.
                let Some(start) = primitive_index(self.builtin_arg(args, 1)?, length, 0) else {
                    return Ok(true);
                };
                let Some(end) = primitive_index(self.builtin_arg(args, 2)?, length, length) else {
                    return Ok(true);
                };
                Ok(!plain_writable_range(object, start, end))
            }
            _ => {
                // Bulk moves already visit O(n) elements. An accessor or hole
                // can invoke guest code, which can change later destinations;
                // execute the WHOLE method generically, not just that element.
                if !self.array_has_dense_data_elements(array) {
                    return Ok(true);
                }
                if kind == K::ArrayShift && !pop_can_use_storage(object, length) {
                    return Ok(true);
                }
                if kind == K::ArrayUnshift {
                    return Ok(!append_targets_absent(object, length, args.count)
                        || !self.array_mutation_plain_prototypes(array)?);
                }
                Ok(false)
            }
        }
    }

    /// A new index may encounter a setter or a read-only inherited property.
    /// Reject exotic prototypes without asking their traps or getters anything.
    /// No receiver scan: normal push remains proportional to the appended count
    /// plus the bounded prototype depth, irrespective of the array's length.
    fn array_mutation_plain_prototypes(&self, array: ObjectId) -> Result<bool, InterpreterError> {
        let Some(object) = self.heap.get(array.0 as usize) else {
            return Ok(false);
        };
        let mut current = self.observable_prototype_link(object, array);
        for _ in 0..MAX_PROTOTYPE_CHAIN_DEPTH {
            let Some(id) = current else {
                return Ok(true);
            };
            if self.proxy_record(id)?.is_some() {
                return Ok(false);
            }
            let Some(object) = self.heap.get(id.0 as usize) else {
                return Ok(false);
            };
            if object.properties.has_index_keys()
                || object.typed_array.is_some()
                || object.primitive_value.is_some()
            {
                return Ok(false);
            }
            current = self.observable_prototype_link(object, id);
        }
        Ok(current.is_none())
    }
}

fn mutation_length(object: &HeapObject) -> Option<u32> {
    let Value::Int(length) = object.properties.get("length")? else {
        return None;
    };
    u32::try_from(*length).ok()
}

fn primitive_index(value: Option<Value>, length: u32, default: u32) -> Option<u32> {
    let number = match value {
        None | Some(Value::Undefined) => return Some(default),
        Some(Value::Int(value)) => value as f64,
        Some(Value::Float(value)) => value.inner(),
        _ => return None,
    };
    let integer = if number.is_nan() { 0.0 } else { number.trunc() };
    Some(if integer < 0.0 {
        (f64::from(length) + integer).max(0.0) as u32
    } else {
        integer.min(f64::from(length)) as u32
    })
}

pub(super) fn plain_writable_range(object: &HeapObject, start: u32, end: u32) -> bool {
    (start..end).all(|index| {
        !matches!(object.properties.get_index(index), None | Some(Value::Accessor { .. }))
            && object.own_property_attributes(&InterpreterCore::generic_index_key(u64::from(index)))
                .writable
    })
}

fn append_targets_absent(object: &HeapObject, length: u32, count: u32) -> bool {
    let Some(end) = length.checked_add(count) else {
        // Keep the spec's partial writes and final invalid-length exception.
        return false;
    };
    (length..end).all(|index| object.properties.get_index(index).is_none())
}

fn pop_can_use_storage(object: &HeapObject, length: u32) -> bool {
    let Some(last) = length.checked_sub(1) else {
        return true;
    };
    if matches!(object.properties.get_index(last), None | Some(Value::Accessor { .. })) {
        return false;
    }
    // Pop reads and deletes, but does not write this index. A non-writable
    // configurable tail is legal; a non-configurable one must throw in order.
    object.own_property_attributes(&InterpreterCore::generic_index_key(u64::from(last)))
        .configurable
}

#[cfg(test)]
mod tests {
    use super::*;

    fn array(length: u32) -> HeapObject {
        let mut object = HeapObject::new();
        object.is_array = true;
        object.properties.insert("length".to_string(), Value::Int(i64::from(length)));
        object
    }

    #[test]
    fn tail_checks_do_not_require_dense_or_writable_preceding_elements() {
        let mut object = array(80_000);
        // No preceding elements at all. Only the last element matters to pop.
        object.properties.insert("79999".to_string(), Value::Int(7));
        assert!(pop_can_use_storage(&object, 80_000));
        assert!(append_targets_absent(&object, 80_000, 2));
        assert!(!append_targets_absent(&object, 79_999, 2));
        object.properties.remove("79999");
        assert!(!pop_can_use_storage(&object, 80_000));
    }

    #[test]
    fn tail_refusal_depends_on_configurability_not_writability() {
        let mut object = array(1);
        object.properties.insert("0".to_string(), Value::Int(3));
        let key = InterpreterCore::generic_index_key(0);
        let mut attributes = object.own_property_attributes(&key);
        attributes.writable = false;
        attributes.configurable = true;
        object.property_attributes.insert(key.clone(), attributes);
        assert!(pop_can_use_storage(&object, 1));
        let mut attributes = object.own_property_attributes(&key);
        attributes.configurable = false;
        object.property_attributes.insert(key, attributes);
        assert!(!pop_can_use_storage(&object, 1));
    }

    #[test]
    fn a_narrow_fill_checks_only_its_write_range() {
        let mut object = array(80_000);
        object.properties.insert("40000".to_string(), Value::Int(7));
        assert!(plain_writable_range(&object, 40_000, 40_001));
        assert!(!plain_writable_range(&object, 39_999, 40_001));
        assert!(plain_writable_range(&object, 80_000, 80_000));
        assert!(plain_writable_range(&object, 7, 2));
        assert_eq!(primitive_index(Some(Value::Int(-3)), 10, 0), Some(7));
        assert_eq!(primitive_index(Some(Value::Int(-30)), 10, 0), Some(0));
        assert_eq!(primitive_index(Some(Value::Int(30)), 10, 0), Some(10));
        assert_eq!(primitive_index(None, 10, 10), Some(10));
        assert_eq!(primitive_index(Some(Value::str("2")), 10, 0), None);
    }

    #[test]
    fn invalid_lengths_and_non_index_tail_writes_take_the_spec_path() {
        let mut object = array(0);
        assert_eq!(mutation_length(&object), Some(0));
        assert!(pop_can_use_storage(&object, 0));
        assert!(append_targets_absent(&object, 0, 0));
        assert!(!append_targets_absent(&object, u32::MAX, 1));
        assert!(!append_targets_absent(&object, u32::MAX - 1, 2));
        for length in [-1, i64::from(u32::MAX) + 1] {
            object.properties.insert("length".to_string(), Value::Int(length));
            assert_eq!(mutation_length(&object), None);
        }
    }
}
