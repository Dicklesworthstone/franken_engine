//! Live, allocation-free index traversal for generic Array methods.
//!
//! A callback, getter or species-result setter may insert a not-yet-visited
//! property, replace a prototype, or delete and recreate a key. A frozen list
//! of present keys cannot implement those methods. This cursor stores only
//! the unvisited interval. Each jump proves absence against the CURRENT
//! ordinary receiver and prototype chain; observable reads still use Has/Get.

use super::*;

const MIN_SPARSE_INTERVAL: u64 = 1 << 16;

/// Both ends refer to the original LengthOfArrayLike, never a later length.
/// A debt of ordinary probes amortizes an inventory over its inspected keys:
/// a long dense prefix must not trigger a full inventory per callback.
pub(super) struct LiveArrayCursor {
    front: u64,
    back: u64,
    backwards: bool,
    sparse: bool,
    probes_left: u64,
}

#[derive(Debug, PartialEq, Eq)]
enum NextIndex {
    Present(u64),
    Exhausted,
    Probe,
}

impl LiveArrayCursor {
    pub(super) fn new(front: u64, back: u64, backwards: bool, visits_holes: bool) -> Self {
        let front = front.min(back);
        Self {
            front, back, backwards,
            sparse: !visits_holes && back - front >= MIN_SPARSE_INTERVAL,
            probes_left: 0,
        }
    }

    /// Return a candidate, not an assertion of presence. The caller still
    /// performs its prescribed HasProperty/Get, including after a sparse jump.
    pub(super) fn next(
        &mut self,
        core: &mut InterpreterCore,
        receiver: ObjectId,
    ) -> Result<Option<u64>, InterpreterError> {
        if self.front == self.back {
            return Ok(None);
        }
        let edge = if self.backwards { self.back - 1 } else { self.front };
        let index = if self.sparse && self.probes_left == 0 {
            let (next, inspected) = core.live_array_like_index(
                receiver, self.front, self.back, self.backwards,
            )?;
            // Sequential probes cannot skip new properties. Rechecking a
            // failed proof later is safe too, even if guest code changes the
            // receiver's shape while this debt is being consumed.
            self.probes_left = inspected.max(1);
            match next {
                NextIndex::Present(index) => index,
                NextIndex::Exhausted => {
                    self.front = self.back;
                    return Ok(None);
                }
                NextIndex::Probe => edge,
            }
        } else {
            self.probes_left = self.probes_left.saturating_sub(1);
            edge
        };
        // A hole may run no guest code at all. The cursor, not an optional
        // callback, owns this work/cancellation check on every yielded step.
        core.charge_native_hole_read()?;
        if self.backwards {
            self.back = index;
        } else {
            self.front = index + 1;
        }
        Ok(Some(index))
    }
}

impl InterpreterCore {
    /// Find the nearest currently present property without executing guest
    /// code or allocating a key inventory. Inherited indices and accessors
    /// are candidates too: their actual Get occurs only AFTER this returns.
    /// No proof or key survives the subsequent observable operation.
    fn live_array_like_index(
        &mut self,
        receiver: ObjectId,
        front: u64,
        back: u64,
        backwards: bool,
    ) -> Result<(NextIndex, u64), InterpreterError> {
        let edge = if backwards { back - 1 } else { front };
        // A present edge needs no absence proof. Preserve an early getter's
        // opportunity to run instead of inspecting unrelated keys first, and
        // do not rescan a large ordinary dense prefix. This selects a PROBE;
        // the caller's real Has/Get still observes proxies and provenance.
        if edge < u64::from(u32::MAX)
            && self.heap.get(receiver.0 as usize)
                .is_some_and(|object| object.properties.get_index(edge as u32).is_some())
        {
            return Ok((NextIndex::Probe, 0));
        }
        let mut current = Some(receiver);
        let mut selected = None;
        let mut inspected = 0_u64;
        for _ in 0..MAX_PROTOTYPE_CHAIN_DEPTH {
            let Some(id) = current else {
                return Ok((selected.map_or(NextIndex::Exhausted, NextIndex::Present), inspected));
            };
            self.charge_native_hole_read()?;
            inspected = inspected.saturating_add(1);
            // A proxy's HasProperty, an exotic indexed object, or provenance
            // on a skipped absence requires the ordinary, metered operations.
            if self.proxy_record(id)?.is_some()
                || self.object_mutation_labels.get(&id)
                    .is_some_and(|label| label != &Label::Public)
            {
                return Ok((NextIndex::Probe, inspected));
            }
            let Some(object) = self.heap.get(id.0 as usize) else {
                return Ok((NextIndex::Probe, inspected));
            };
            if object.is_array || object.typed_array.is_some() || object.primitive_value.is_some()
                || !object.property_labels.exact_is_empty()
            {
                return Ok((NextIndex::Probe, inspected));
            }
            if back <= u64::from(u32::MAX) {
                // Canonical numeric keys already have an ordered index. Do not
                // walk or parse the entire property dictionary to find its next
                // entry. The bounded holey search may return an absent boundary;
                // Has/Get below remains authoritative for that candidate.
                let (candidate, work) = object.properties
                    .probe_index_key(front as u32..back as u32, backwards);
                for _ in 0..work {
                    self.charge_native_hole_read()?;
                }
                inspected = inspected.saturating_add(work as u64);
                if let Some(index) = candidate.map(u64::from)
                    && selected.is_none_or(|previous| {
                        if backwards { index > previous } else { index < previous }
                    })
                {
                    selected = Some(index);
                }
                let object = self.heap.get(id.0 as usize)
                    .expect("no guest call changed the receiver");
                current = self.observable_prototype_link(object, id);
                continue;
            }
            let count = object.properties.exact_len();
            // Precharge the entire retained carrier before walking it. A
            // large named-key dictionary must not hide an unmetered scan.
            // This check runs no guest callback and needs no temporary buffer.
            for _ in 0..count {
                self.charge_native_hole_read()?;
            }
            inspected = inspected.saturating_add(count as u64);
            let object = self.heap.get(id.0 as usize).expect("no guest call changed the receiver");
            for (key, _) in object.properties.well_formed_data_entries() {
                if let Some(index) = array_like_index(key)
                    && front <= index && index < back
                    && selected.is_none_or(|previous| {
                        if backwards { index > previous } else { index < previous }
                    })
                {
                    selected = Some(index);
                }
            }
            current = self.observable_prototype_link(object, id);
        }
        // A bounded proof that cannot reach the end is NOT proof of absence.
        Ok((if current.is_none() {
            selected.map_or(NextIndex::Exhausted, NextIndex::Present)
        } else {
            NextIndex::Probe
        }, inspected))
    }
}

/// Generic Array methods accept indices beyond the Array exotic's u32 range.
/// Parse canonical decimal names without allocating index.to_string(). Exact
/// lone-surrogate names cannot be decimal indices and are not enumerated here.
fn array_like_index(key: &str) -> Option<u64> {
    let (&first, rest) = key.as_bytes().split_first()?;
    if !first.is_ascii_digit() || (first == b'0' && !rest.is_empty()) || rest.len() > 15 {
        return None;
    }
    let mut index = u64::from(first - b'0');
    for &byte in rest {
        if !byte.is_ascii_digit() { return None; }
        index = index.checked_mul(10)?.checked_add(u64::from(byte - b'0'))?;
    }
    (index < MAX_SAFE_LENGTH).then_some(index)
}

#[cfg(test)]
mod tests;
