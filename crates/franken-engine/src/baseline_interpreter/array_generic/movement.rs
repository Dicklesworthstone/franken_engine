//! Live sparse moves shared by Array mutation algorithms.
//!
//! A missing source still deletes its destination. Seeking only source keys
//! would therefore leave stale destination properties behind. Seek both CURRENT
//! intervals and stop at the first candidate in either, without retaining any
//! candidate across a getter, setter or proxy operation. Actual moves remain
//! HasProperty/Get/Set/Delete through the existing native property machinery.

use super::*;
use super::iteration::{MIN_SPARSE_INTERVAL, NextIndex};

struct MoveCursor {
    source: u64,
    target: u64,
    // Linear targets advance with the source. Reverse pairs instead use an
    // exclusive upper bound and approach the untouched midpoint from above.
    mirrored: bool,
    front: u64,
    back: u64,
    backwards: bool,
    sparse: bool,
    probes_left: u64,
}

impl MoveCursor {
    fn new(source: u64, target: u64, count: u64, backwards: bool) -> Self {
        // Every caller has already performed its method's length/coercion
        // checks. All arithmetic below is within the original safe interval.
        debug_assert!(source <= MAX_SAFE_LENGTH && count <= MAX_SAFE_LENGTH - source);
        debug_assert!(target <= MAX_SAFE_LENGTH && count <= MAX_SAFE_LENGTH - target);
        Self {
            source,
            target,
            mirrored: false,
            front: 0,
            back: count,
            backwards,
            sparse: count >= MIN_SPARSE_INTERVAL,
            probes_left: 0,
        }
    }

    fn mirrored(length: u64) -> Self {
        debug_assert!(length <= MAX_SAFE_LENGTH);
        let count = length / 2;
        Self {
            source: 0,
            target: length,
            mirrored: true,
            front: 0,
            back: count,
            backwards: false,
            sparse: count >= MIN_SPARSE_INTERVAL,
            probes_left: 0,
        }
    }

    fn target_range(&self) -> (u64, u64, bool) {
        if self.mirrored {
            (self.target - self.back, self.target - self.front, true)
        } else {
            (self.target + self.front, self.target + self.back, self.backwards)
        }
    }

    fn target_offset(&self, candidate: NextIndex, edge: u64) -> Option<u64> {
        match candidate {
            NextIndex::Present(index) if self.mirrored => Some(self.target - 1 - index),
            other => candidate_offset(other, self.target, edge),
        }
    }

    fn next(
        &mut self,
        core: &mut InterpreterCore,
        object: ObjectId,
    ) -> Result<Option<(u64, u64)>, InterpreterError> {
        if self.front == self.back {
            return Ok(None);
        }
        let edge = if self.backwards { self.back - 1 } else { self.front };
        let mut offset = edge;
        // Unlike a read-only cursor, this may omit absent Delete operations.
        // Retain ordinary writes whenever current control/callback provenance
        // is non-public, even if the receiver's own metadata is still public.
        if self.sparse && self.probes_left == 0
            && core.active_execution_context_label()
            .is_none_or(|label| label == &Label::Public)
            && core.active_inline_callback_context_label.as_ref()
                .is_none_or(|label| label == &Label::Public)
            && core.pending_hostcall_result_label.as_ref()
                .is_none_or(|label| label == &Label::Public)
        {
            let (source, source_work) = core.live_array_like_index(
                object,
                self.source + self.front,
                self.source + self.back,
                self.backwards,
            )?;
            self.probes_left = source_work.max(1);
            let source = candidate_offset(source, self.source, edge);
            // A source at the current edge must run immediately. Do not scan
            // unrelated destination metadata before its getter can throw.
            if source != Some(edge) {
                let (target_front, target_back, target_backwards) = self.target_range();
                let (target, target_work) = core.live_array_like_index(
                    object, target_front, target_back, target_backwards,
                )?;
                self.probes_left = source_work.saturating_add(target_work).max(1);
                let target = self.target_offset(target, edge);
                let next = match (source, target) {
                    (Some(a), Some(b)) => Some(if self.backwards { a.max(b) } else { a.min(b) }),
                    (Some(index), None) | (None, Some(index)) => Some(index),
                    (None, None) => None,
                };
                let Some(next) = next else {
                    self.front = self.back;
                    return Ok(None);
                };
                offset = next;
            }
        } else {
            // Sequential work amortizes inventories of wide/named indices and
            // inherited dense prefixes. It cannot skip callback-created keys.
            self.probes_left = self.probes_left.saturating_sub(1);
        }
        if self.backwards {
            self.back = offset;
        } else {
            self.front = offset + 1;
        }
        // The caller owns the per-pair work check, including empty pairs.
        // Seeking separately charges its bounded storage/prototype probes.
        let target = if self.mirrored {
            self.target - 1 - offset
        } else {
            self.target + offset
        };
        Ok(Some((self.source + offset, target)))
    }
}

fn candidate_offset(candidate: NextIndex, base: u64, edge: u64) -> Option<u64> {
    match candidate {
        NextIndex::Present(index) => Some(index - base),
        NextIndex::Exhausted => None,
        NextIndex::Probe => Some(edge),
    }
}

impl InterpreterCore {
    /// Reverse visits lower Has/Get before upper Has/Get, then writes in the
    /// specification's order. A move in each direction would read changed
    /// values and reorder getters. Hold both values before either write.
    /// Only pairs proved absent on BOTH sides may be skipped, and no proof
    /// survives a getter, setter, proxy trap or nested reversal.
    pub(super) fn generic_reverse_properties(
        &mut self,
        module: Option<&Ir3Module>,
        object: ObjectId,
        length: u64,
    ) -> Result<(), InterpreterError> {
        let mut cursor = MoveCursor::mirrored(length);
        while let Some((lower, upper)) = cursor.next(self, object)? {
            self.charge_native_hole_read()?;
            let lower_key = Self::generic_index_key(lower);
            let upper_key = Self::generic_index_key(upper);
            let lower_exists = self.generic_has(module, object, &lower_key)?;
            self.observe_scoped_callback_result()?;
            let lower_value = if lower_exists {
                let value = self.generic_get(module, object, &lower_key)?;
                self.observe_scoped_callback_result()?;
                value
            } else {
                Value::Undefined
            };
            let upper_exists = self.generic_has(module, object, &upper_key)?;
            self.observe_scoped_callback_result()?;
            let upper_value = if upper_exists {
                let value = self.generic_get(module, object, &upper_key)?;
                self.observe_scoped_callback_result()?;
                value
            } else {
                Value::Undefined
            };
            match (lower_exists, upper_exists) {
                (true, true) => {
                    self.generic_set(module, object, &lower_key, upper_value)?;
                    self.observe_scoped_callback_result()?;
                    self.generic_set(module, object, &upper_key, lower_value)?;
                }
                (false, true) => {
                    self.generic_set(module, object, &lower_key, upper_value)?;
                    self.observe_scoped_callback_result()?;
                    self.generic_delete(module, object, &upper_key)?;
                }
                (true, false) => {
                    self.generic_delete(module, object, &lower_key)?;
                    self.observe_scoped_callback_result()?;
                    self.generic_set(module, object, &upper_key, lower_value)?;
                }
                (false, false) => {}
            }
            self.observe_scoped_callback_result()?;
        }
        Ok(())
    }

    /// Move in the caller's prescribed direction. Both ranges belong to the
    /// same receiver, so overlap and source/destination aliasing stay live.
    pub(super) fn generic_move_range(
        &mut self,
        module: Option<&Ir3Module>,
        object: ObjectId,
        source: u64,
        target: u64,
        count: u64,
        backwards: bool,
    ) -> Result<(), InterpreterError> {
        let mut cursor = MoveCursor::new(source, target, count, backwards);
        while let Some((from, to)) = cursor.next(self, object)? {
            self.generic_move(module, object, from, to)?;
        }
        Ok(())
    }

    /// Delete a captured interval without reading its values. Identical
    /// source/target ranges reuse the live move cursor's absence proof and
    /// provenance gates. Inherited candidates are harmless conservative work;
    /// only the actual receiver's [[Delete]] is invoked, never Has or Get.
    pub(super) fn generic_delete_range(
        &mut self,
        module: Option<&Ir3Module>,
        object: ObjectId,
        start: u64,
        count: u64,
        backwards: bool,
    ) -> Result<(), InterpreterError> {
        let mut cursor = MoveCursor::new(start, start, count, backwards);
        while let Some((index, _)) = cursor.next(self, object)? {
            self.charge_native_hole_read()?;
            self.generic_delete(module, object, &Self::generic_index_key(index))?;
            self.observe_scoped_callback_result()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod reverse_tests;
