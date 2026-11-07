//! Flat source records for JSON revivers.
//!
//! Record edges are arena indices rather than recursively owned children.
//! Building, deduplicating, consuming, and abandoning records all use bounded
//! native stack space, including errors before any reviver callback runs.

use super::*;

#[derive(Clone, Copy)]
enum RecordId {
    Root,
    Node(usize),
}

#[derive(Clone, Copy)]
struct RecordFrame {
    id: RecordId,
    close: u16,
}

impl JsonParseRecords {
    fn record(&self, id: RecordId) -> &JsonParseRecord {
        match id {
            RecordId::Root => &self.root,
            RecordId::Node(index) => self.nodes[index].as_ref().expect("unconsumed parse record"),
        }
    }

    fn record_mut(&mut self, id: RecordId) -> &mut JsonParseRecord {
        match id {
            RecordId::Root => &mut self.root,
            RecordId::Node(index) => self.nodes[index].as_mut().expect("unconsumed parse record"),
        }
    }
}

fn new_record(value: Value) -> JsonParseRecord {
    JsonParseRecord {
        value,
        source: None,
        elements: Vec::new(),
        entries: Vec::new(),
    }
}

impl InterpreterCore {
    /// Describe validated JSON before guest code runs. Primitive spellings
    /// remain spans in the input; object indices retain the final duplicate.
    /// The caller owns every successful reservation in charged until all
    /// callbacks, replaced records, and error paths have released the arena.
    pub(super) fn json_parse_record(
        &mut self,
        units: &[u16],
        pos: &mut usize,
        value: Value,
        charged: &mut u64,
    ) -> Result<JsonParseRecords, InterpreterError> {
        self.json_charge_work()?;
        let root_bytes = std::mem::size_of::<JsonParseRecord>() as u64;
        self.json_reserve_temporary(root_bytes)?;
        *charged += root_bytes;
        let mut records = JsonParseRecords {
            root: new_record(value),
            nodes: Vec::new(),
        };
        let mut frames = Vec::<RecordFrame>::new();
        let mut frame_bytes = 0_u64;
        let outcome = (|| {
            let Some(close) = Self::json_begin_source_record(&mut records.root, units, pos) else {
                return Ok(());
            };
            self.json_reserve_record_slot(&mut frames, &mut frame_bytes)?;
            frames.push(RecordFrame {
                id: RecordId::Root,
                close,
            });
            while let Some(frame) = frames.last().copied() {
                // Charge both descent and the possibly very long closing
                // suffix, without relying on a JavaScript recursion limit.
                self.json_charge_work()?;
                Self::json_skip_ws(units, pos);
                if units.get(*pos) == Some(&frame.close) {
                    if frame.close == 0x7D {
                        records.record_mut(frame.id).finish_entries();
                    }
                    *pos += 1;
                    frames.pop();
                    Self::json_skip_ws(units, pos);
                    if units.get(*pos) == Some(&0x2C) {
                        *pos += 1;
                    }
                    continue;
                }
                let object = frame.close == 0x7D;
                let key = if object {
                    let Some(key) = Self::json_parse_string(units, pos) else {
                        return Err(Self::json_source_record_error());
                    };
                    Self::json_skip_ws(units, pos);
                    if units.get(*pos) != Some(&0x3A) {
                        return Err(Self::json_source_record_error());
                    }
                    *pos += 1;
                    key
                } else {
                    JsString::from(records.record(frame.id).elements.len().to_string())
                };
                self.json_reserve_record_slot(&mut records.nodes, charged)?;
                let value = self.json_parsed_child(&records.record(frame.id).value, &key);
                let mut child = new_record(value);
                let child_close = Self::json_begin_source_record(&mut child, units, pos);
                let index = records.nodes.len();
                records.nodes.push(Some(child));
                let parent = records.record_mut(frame.id);
                if object {
                    self.json_reserve_record_slot(&mut parent.entries, charged)?;
                    let key_bytes = Self::estimate_js_string_bytes(&key);
                    self.json_reserve_temporary(key_bytes)?;
                    *charged += key_bytes;
                    parent.entries.push(JsonParseRecordEntry {
                        key,
                        ordinal: parent.entries.len(),
                        record: Some(index),
                    });
                } else {
                    self.json_reserve_record_slot(&mut parent.elements, charged)?;
                    parent.elements.push(Some(index));
                }
                if let Some(close) = child_close {
                    self.json_reserve_record_slot(&mut frames, &mut frame_bytes)?;
                    frames.push(RecordFrame {
                        id: RecordId::Node(index),
                        close,
                    });
                } else {
                    Self::json_skip_ws(units, pos);
                    if units.get(*pos) == Some(&0x2C) {
                        *pos += 1;
                    }
                }
            }
            Ok(())
        })();
        drop(frames);
        self.json_release_temporary(frame_bytes);
        outcome?;
        Ok(records)
    }

    fn json_begin_source_record(
        record: &mut JsonParseRecord,
        units: &[u16],
        pos: &mut usize,
    ) -> Option<u16> {
        Self::json_skip_ws(units, pos);
        let start = *pos;
        match units.get(*pos) {
            Some(0x7B) => {
                *pos += 1;
                Some(0x7D)
            }
            Some(0x5B) => {
                *pos += 1;
                Some(0x5D)
            }
            _ => {
                *pos = json_primitive_source_end(units, start);
                record.source = Some(start.min(*pos)..*pos);
                None
            }
        }
    }

    fn json_source_record_error() -> InterpreterError {
        InterpreterError::TypeError {
            expected: "validated JSON source for reviver records".to_string(),
            got: "inconsistent source cursor".to_string(),
        }
    }

    /// Admit an allocation's peak before growing it. Spare capacity belongs
    /// to this operation even after its last live element has been popped.
    pub(super) fn json_reserve_record_slot<T>(
        &mut self,
        values: &mut Vec<T>,
        charged: &mut u64,
    ) -> Result<(), InterpreterError> {
        if values.len() < values.capacity() {
            return Ok(());
        }
        let capacity = values
            .capacity()
            .checked_add(values.capacity().max(1))
            .ok_or_else(|| self.memory_budget_error(u64::MAX, self.heap_object_count_u32()))?;
        let bytes = capacity
            .checked_mul(std::mem::size_of::<T>())
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(|| self.memory_budget_error(u64::MAX, self.heap_object_count_u32()))?;
        self.json_reserve_temporary(bytes)?;
        *charged += bytes;
        let old_bytes = (values.capacity() * std::mem::size_of::<T>()) as u64;
        values
            .try_reserve_exact(capacity - values.len())
            .map_err(|_| self.memory_budget_error(u64::MAX, self.heap_object_count_u32()))?;
        let actual_bytes = values
            .capacity()
            .checked_mul(std::mem::size_of::<T>())
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(|| self.memory_budget_error(u64::MAX, self.heap_object_count_u32()))?;
        if actual_bytes > bytes {
            self.json_reserve_temporary(actual_bytes - bytes)?;
            *charged += actual_bytes - bytes;
        }
        self.json_release_temporary(old_bytes);
        *charged -= old_bytes;
        Ok(())
    }
}
