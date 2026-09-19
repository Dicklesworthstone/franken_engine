//! Instance-owned table32 funcref storage and checked indirect dispatch.
//!
//! Active, passive and declarative elements accept function-index vectors and
//! ref.func/ref.null constant expressions. All references are validated before
//! publication. Active/declarative elements are unavailable before startup;
//! passive elements remain readable until dropped in that instance. Bulk writes
//! check both ranges and charge work before mutation. Reference-valued stack
//! instructions, typed references and imported tables remain refused.

use super::*;
use std::sync::Arc;

#[derive(Debug, Clone)]
struct TableType {
    minimum: u32,
    maximum: u32,
}

#[derive(Debug, Clone, Copy)]
enum ElementMode {
    Active { table: u32, offset: u32 },
    Passive,
    Declarative,
}

// Immutable module-owned payload; an instance only owns its availability flag.
// Sharing these bytes never shares mutable table contents or drop state.
type ElementEntries = Arc<Vec<Option<u32>>>;

#[derive(Debug, Clone)]
struct ElementSegment {
    mode: ElementMode,
    entries: ElementEntries,
}

#[derive(Debug, Clone, Default)]
pub(super) struct TablePlan {
    types: Vec<TableType>,
    elements: Vec<ElementSegment>,
    // Includes table records, initial slots, segment records and their entries.
    // Combined with globals/data by ModuleState, not a separate parallel cap.
    records: usize,
}

impl TablePlan {
    pub(super) fn records(&self) -> usize {
        self.records
    }

    fn admit(&mut self, count: usize, other: usize, limits: &WasmNumericLimits) -> Result<(), WasmNumericVmError> {
        let next = self.records.checked_add(count);
        let actual = next.and_then(|next| next.checked_add(other));
        if actual.is_none_or(|actual| actual > limits.max_state_entries) {
            return Err(WasmStateError::LimitExceeded {
                resource: "instance state records".into(),
                actual: actual.map_or(u64::MAX, |actual| actual as u64),
                max: limits.max_state_entries as u64,
            }.into());
        }
        self.records = next.expect("checked table record sum");
        Ok(())
    }

    pub(super) fn parse_tables(&mut self, reader: &mut ByteReader<'_>, limits: &WasmNumericLimits, other: usize) -> Result<(), WasmNumericVmError> {
        let count = reader.read_u32_leb()? as usize;
        self.admit(count, other, limits)?;
        for _ in 0..count {
            if reader.read_u8()? != 0x70 {
                return Err(invalid("only nullable funcref tables are supported"));
            }
            let flags = reader.read_u8()?;
            if flags > 1 {
                return Err(invalid("only unshared table32 limits are supported"));
            }
            let minimum = reader.read_u32_leb()?;
            let maximum = if flags == 1 { reader.read_u32_leb()? } else { u32::MAX };
            if minimum > maximum {
                return Err(invalid("table minimum exceeds maximum"));
            }
            self.admit(minimum as usize, other, limits)?;
            self.types.try_reserve(1).map_err(|_| allocation::<TableType>(count))?;
            self.types.push(TableType { minimum, maximum });
        }
        Ok(())
    }

    pub(super) fn validate_table(&self, index: u32) -> Result<(), WasmNumericVmError> {
        self.table(index).map(|_| ())
    }

    fn table(&self, index: u32) -> Result<&TableType, WasmNumericVmError> {
        self.types.get(index as usize)
            .ok_or_else(|| WasmStateError::UnknownTable { table_index: index }.into())
    }

    pub(super) fn parse_elements(&mut self, reader: &mut ByteReader<'_>, limits: &WasmNumericLimits, other: usize) -> Result<(), WasmNumericVmError> {
        let count = reader.read_u32_leb()? as usize;
        self.admit(count, other, limits)?;
        for _ in 0..count {
            let mode = reader.read_u32_leb()?;
            if mode > 7 {
                return Err(invalid("unsupported element segment mode"));
            }
            let segment_mode = if mode & 1 == 0 {
                let table = if mode & 2 != 0 { reader.read_u32_leb()? } else { 0 };
                self.validate_table(table)?;
                let WasmBoundaryValue::I32(offset) = numeric_constant(reader)? else {
                    return Err(invalid("element offset must be i32.const"));
                };
                ElementMode::Active { table, offset: offset as u32 }
            } else if mode & 2 == 0 {
                ElementMode::Passive
            } else {
                ElementMode::Declarative
            };
            // Encodings 0/4 imply their reference type. Every other mode has
            // elemkind (indices) or reftype (expressions), without an offset
            // or table immediate in passive/declarative modes.
            if mode & 3 != 0 {
                let expected = if mode & 4 == 0 { 0 } else { 0x70 };
                if reader.read_u8()? != expected {
                    return Err(invalid("element reference type must be nullable funcref"));
                }
            }
            let length = reader.read_u32_leb()? as usize;
            self.admit(length, other, limits)?;
            // Each element needs at least one encoded byte. Refuse truncated
            // vectors before a length-controlled allocation, even with huge caps.
            if length > reader.remaining().len() {
                return Err(invalid("truncated element vector"));
            }
            let mut entries = Vec::new();
            entries.try_reserve_exact(length).map_err(|_| allocation::<Option<u32>>(length))?;
            for _ in 0..length {
                let entry = if mode & 4 == 0 {
                    Some(reader.read_u32_leb()?)
                } else {
                    let entry = match reader.read_u8()? {
                        0xd2 => Some(reader.read_u32_leb()?),
                        0xd0 => {
                            let (heap_type, length) = read_signed_leb(reader.remaining(), 33, 5)?;
                            reader.offset += length;
                            if heap_type != -16 {
                                return Err(invalid("ref.null initializer must have func heap type"));
                            }
                            None
                        }
                        _ => return Err(invalid("unsupported element constant expression")),
                    };
                    if reader.read_u8()? != 0x0b {
                        return Err(invalid("element initializer has trailing instructions"));
                    }
                    entry
                };
                entries.push(entry);
            }
            self.elements.try_reserve(1).map_err(|_| allocation::<ElementSegment>(count))?;
            self.elements.push(ElementSegment { mode: segment_mode, entries: Arc::new(entries) });
        }
        Ok(())
    }

    pub(super) fn validate_element(&self, index: u32) -> Result<(), WasmNumericVmError> {
        if self.elements.get(index as usize).is_none() {
            return Err(invalid(format!("unknown element segment {index}")));
        }
        Ok(())
    }

    pub(super) fn validate_functions(&self, vm: &WasmNumericVm) -> Result<(), WasmNumericVmError> {
        for segment in &self.elements {
            for function in segment.entries.iter().flatten() {
                // Imported indices participate in the function index space,
                // but invoking them still requires the existing host boundary.
                vm.function_signature(*function)?;
            }
        }
        Ok(())
    }

    pub(super) fn instantiate(&self) -> Result<InstanceTables, WasmNumericVmError> {
        for (segment, element) in self.elements.iter().enumerate() {
            let ElementMode::Active { table, offset } = element.mode else { continue; };
            let size = self.table(table)?.minimum;
            if u64::from(offset) + element.entries.len() as u64 > u64::from(size) {
                return Err(WasmStateError::ElementSegmentOutOfBounds {
                    segment, table_index: table, offset,
                    length: element.entries.len(), table_size: size,
                }.into());
            }
        }
        let mut tables = Vec::new();
        tables.try_reserve_exact(self.types.len()).map_err(|_| allocation::<Vec<Option<u32>>>(self.types.len()))?;
        for ty in &self.types {
            debug_assert!(ty.minimum <= ty.maximum);
            let mut entries = Vec::new();
            entries.try_reserve_exact(ty.minimum as usize).map_err(|_| allocation::<Option<u32>>(ty.minimum as usize))?;
            entries.resize(ty.minimum as usize, None);
            tables.push(entries);
        }
        // Source order matters: later segments replace overlapping entries,
        // including explicit nulls. No guest code runs during initialization.
        let mut elements = Vec::new();
        elements.try_reserve_exact(self.elements.len())
            .map_err(|_| allocation::<Option<ElementEntries>>(self.elements.len()))?;
        for element in &self.elements {
            if let ElementMode::Active { table, offset } = element.mode {
                let start = offset as usize;
                tables[table as usize][start..start + element.entries.len()]
                    .copy_from_slice(element.entries.as_slice());
            }
            // Active and declarative segments are dropped before a start
            // function can observe them. Preserve indices as empty slots.
            elements.push(if matches!(element.mode, ElementMode::Passive) {
                Some(Arc::clone(&element.entries))
            } else {
                None
            });
        }
        Ok(InstanceTables { tables, elements })
    }
}

fn allocation<T>(count: usize) -> WasmStateError {
    WasmStateError::AllocationFailed {
        bytes: (count as u64).saturating_mul(std::mem::size_of::<T>() as u64),
    }
}

#[derive(Debug)]
pub(super) struct InstanceTables {
    tables: Vec<Vec<Option<u32>>>,
    elements: Vec<Option<ElementEntries>>,
}

impl InstanceTables {
    pub(super) fn export(&self, table: u32) -> Option<&[Option<u32>]> {
        self.tables.get(table as usize).map(Vec::as_slice)
    }

    pub(super) fn size(&self, table_index: u32) -> Result<u32, WasmNumericVmError> {
        self.tables.get(table_index as usize).map(|table| table.len() as u32)
            .ok_or_else(|| WasmStateError::UnknownTable { table_index }.into())
    }

    fn range(&self, table_index: u32, offset: u32, length: u32) -> Result<std::ops::Range<usize>, WasmNumericVmError> {
        let size = self.size(table_index)?;
        let end = u64::from(offset) + u64::from(length);
        if end > u64::from(size) {
            // Report the first invalid element, including a zero-length range
            // starting beyond the end. The addition must never wrap at 2^32.
            return Err(WasmStateError::TableElementOutOfBounds {
                table_index, element_index: offset.max(size), table_size: size,
            }.into());
        }
        Ok(offset as usize..end as usize)
    }

    pub(super) fn copy(
        &mut self, destination_table: u32, source_table: u32,
        destination: u32, source: u32, length: u32, meter: &mut ExecutionMeter<'_>,
    ) -> Result<(), WasmNumericVmError> {
        let destination_range = self.range(destination_table, destination, length)?;
        let source_range = self.range(source_table, source, length)?;
        // One unit per reference, independent of the host's Option layout.
        // Both bounds and the entire charge precede the first changed slot.
        // No temporary vector or new callable authority is introduced.
        meter.charge_work(u64::from(length))?;
        if destination_table == source_table {
            self.tables[destination_table as usize].copy_within(source_range, destination_range.start);
        } else if destination_table < source_table {
            let (before, after) = self.tables.split_at_mut(source_table as usize);
            before[destination_table as usize][destination_range].copy_from_slice(&after[0][source_range]);
        } else {
            let (before, after) = self.tables.split_at_mut(destination_table as usize);
            after[0][destination_range].copy_from_slice(&before[source_table as usize][source_range]);
        }
        Ok(())
    }

    pub(super) fn init(
        &mut self, table: u32, element: u32, destination: u32,
        source: u32, length: u32, meter: &mut ExecutionMeter<'_>,
    ) -> Result<(), WasmNumericVmError> {
        let destination_range = self.range(table, destination, length)?;
        let entries = self.elements.get(element as usize)
            .ok_or_else(|| invalid(format!("unknown validated element segment {element}")))?
            .as_ref().map_or(&[][..], |entries| entries.as_slice());
        let end = u64::from(source) + u64::from(length);
        if end > entries.len() as u64 {
            // This is the source segment's extent, NOT the destination table
            // extent or the embedding's allocation ceiling. Retain both bounds
            // in the existing structured state-limit error channel.
            return Err(WasmStateError::LimitExceeded {
                resource: format!("element segment {element} source range"),
                actual: end, max: entries.len() as u64,
            }.into());
        }
        meter.charge_work(u64::from(length))?;
        self.tables[table as usize][destination_range]
            .copy_from_slice(&entries[source as usize..end as usize]);
        Ok(())
    }

    pub(super) fn drop_element(&mut self, element: u32) -> Result<(), WasmNumericVmError> {
        let slot = self.elements.get_mut(element as usize)
            .ok_or_else(|| invalid(format!("unknown validated element segment {element}")))?;
        // Idempotent and local to this instance. The module's immutable plan
        // and other instances retain their own references. No per-entry walk.
        *slot = None;
        Ok(())
    }

    pub(super) fn resolve(&self, vm: &WasmNumericVm, type_index: u32, table_index: u32, element_index: u32, meter: &mut ExecutionMeter<'_>) -> Result<u32, WasmNumericVmError> {
        let expected = vm.function_type(type_index)?;
        let table = self.tables.get(table_index as usize)
            .ok_or(WasmStateError::UnknownTable { table_index })?;
        let callee = table.get(element_index as usize)
            .ok_or(WasmStateError::TableElementOutOfBounds {
                table_index, element_index, table_size: table.len() as u32,
            })?
            .ok_or(WasmStateError::UninitializedTableElement { table_index, element_index })?;
        let actual = vm.function_signature(callee)?;
        // Signature equality is structural, not type-index identity. Duplicate
        // type declarations are legal. Charge comparison work before entering
        // any guest callee, using the same meter as direct and recursive calls.
        meter.charge_work((expected.params.len().saturating_add(expected.results.len()) as u64).div_ceil(64))?;
        if expected.params != actual.params || expected.results != actual.results {
            return Err(WasmStateError::IndirectCallTypeMismatch { function_index: callee, type_index }.into());
        }
        Ok(callee)
    }
}

#[cfg(test)]
#[path = "tables/tests.rs"]
mod tests;
