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
            front: 0,
            back: count,
            backwards,
            sparse: count >= MIN_SPARSE_INTERVAL,
            probes_left: 0,
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
                let (target, target_work) = core.live_array_like_index(
                    object,
                    self.target + self.front,
                    self.target + self.back,
                    self.backwards,
                )?;
                self.probes_left = source_work.saturating_add(target_work).max(1);
                let target = candidate_offset(target, self.target, edge);
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
        // generic_move owns the per-yield work check, including empty pairs.
        // Seeking separately charges its bounded storage/prototype probes.
        Ok(Some((self.source + offset, self.target + offset)))
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
}

#[cfg(test)]
mod tests;
