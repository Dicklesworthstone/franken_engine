//! Refresh registered views without a cloned candidate or survivor vector.
//!
//! No guest callback or collection runs during this operation. Refresh first
//! in the original registry order; only after all fallible view updates have
//! succeeded may stable compaction change that registry. On a failed update,
//! its complete original discovery list remains available for a later retry.

use super::*;

fn belongs_to_buffer(object: &HeapObject, buffer: ObjectId) -> bool {
    object
        .typed_array
        .as_ref()
        .is_some_and(|view| view.buffer == buffer)
        || object
            .data_view
            .as_ref()
            .is_some_and(|view| view.buffer == buffer)
}

impl InterpreterCore {
    pub(super) fn refresh_registered_buffer_views(
        &mut self,
        buffer: ObjectId,
    ) -> Result<(), InterpreterError> {
        let backing = self.buffer_backing(buffer)?;
        debug_assert!(backing.max_byte_length.is_some());
        let (buffer_len, detached, count) =
            (backing.bytes.len(), backing.detached, backing.views.len());
        let mut live = 0;
        for index in 0..count {
            // Copy only this ID, then release the immutable buffer borrow.
            // View refresh cannot alter the registry, invoke guest code, or
            // collect. In particular, duplicate IDs retain their old order.
            let view_id = self.buffer_backing(buffer)?.views[index];
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
                live += 1;
            }
        }
        if live == count {
            return Ok(());
        }

        // Preserve the existing registry's length-based estimate and release
        // order. Do not compact a prefix while a subsequent view can still
        // refuse admission: that would corrupt its original retry sequence.
        let object = self
            .heap
            .get(buffer.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: buffer.0 })?;
        let previous = Self::estimate_heap_object_bytes(object);
        let entry = std::mem::size_of::<ObjectId>() as u64;
        let next = previous
            .saturating_sub(count as u64 * entry)
            .saturating_add(live as u64 * entry);
        self.apply_memory_component_delta(previous, next)?;
        self.mutate_heap(|heap| {
            let mut write = 0;
            for read in 0..count {
                let id = heap
                    .get(buffer.0 as usize)
                    .and_then(|object| object.array_buffer.as_deref())
                    .expect("registered buffer stays live during refresh")
                    .views[read];
                if heap
                    .get(id.0 as usize)
                    .is_some_and(|object| belongs_to_buffer(object, buffer))
                {
                    if write != read {
                        heap.get_mut(buffer.0 as usize)
                            .and_then(|object| object.array_buffer.as_deref_mut())
                            .expect("registered buffer stays live during compaction")
                            .views[write] = id;
                    }
                    write += 1;
                }
            }
            debug_assert_eq!(write, live);
            // Reuse this allocation, including its spare capacity. No source
            // payload, view object, or registry snapshot is copied or retained.
            heap.get_mut(buffer.0 as usize)
                .and_then(|object| object.array_buffer.as_deref_mut())
                .expect("registered buffer stays live during compaction")
                .views
                .truncate(live);
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests;
