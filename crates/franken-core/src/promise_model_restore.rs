//! Fail-closed reconstruction of deterministic Promise stores and task queues.
//!
//! Serialized queue fields form one state machine; individually well-typed
//! fields are not enough. Validate their relationships before exposing a
//! restored queue to scheduling, compaction, or memory accounting. This does
//! not authenticate snapshots or replace the caller's decode-size budget.

use std::collections::{BTreeSet, BinaryHeap};

use serde::de::Error as _;
use serde::{Deserialize, Deserializer};

use super::{
    MacrotaskHeapEntry, MacrotaskQueue, MacrotaskSource, Microtask, MicrotaskQueue, PromiseSlots,
    PromiseStore, WitnessEvent, WitnessLog,
};

impl<'de> Deserialize<'de> for PromiseStore {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename = "PromiseStore")]
        struct Snapshot {
            promises: PromiseSlots,
            next_seq: u64,
            witness: WitnessLog,
        }

        let snapshot = Snapshot::deserialize(deserializer)?;
        let allocated = u64::try_from(snapshot.promises.len()).map_err(D::Error::custom)?;
        // Creation advances both frontiers, and rollback rewinds both. A
        // restored counter must not alias earlier identities or overflow on
        // the next create, even when every individual field decoded correctly.
        if allocated > u64::from(u32::MAX) || snapshot.next_seq != allocated {
            return Err(D::Error::custom(
                "promise creation frontier differs from allocated slots",
            ));
        }
        for (index, record) in snapshot.promises.iter().enumerate() {
            if u64::from(record.handle.0) != index as u64 || record.creation_seq != index as u64 {
                return Err(D::Error::custom(
                    "promise identity does not match its arena slot",
                ));
            }
            // Settlement drains the stored reactions before exposing state.
            // Otherwise a restored settled source would silently strand jobs.
            if record.state.is_settled() && !record.reactions.is_empty() {
                return Err(D::Error::custom(
                    "settled promise retains pending reactions",
                ));
            }
        }
        Ok(Self {
            promises: snapshot.promises,
            next_seq: snapshot.next_seq,
            witness: snapshot.witness,
        })
    }
}

impl<'de> Deserialize<'de> for MicrotaskQueue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Preserve the existing field order, names, and required-field rules.
        #[derive(Deserialize)]
        #[serde(rename = "MicrotaskQueue")]
        struct Snapshot {
            tasks: Vec<Microtask>,
            cursor: usize,
            enqueue_count: u64,
            witness: Vec<WitnessEvent>,
        }

        let snapshot = Snapshot::deserialize(deserializer)?;
        if snapshot.cursor > snapshot.tasks.len() {
            return Err(D::Error::custom("microtask cursor exceeds buffer length"));
        }
        let retained = u64::try_from(snapshot.tasks.len()).map_err(D::Error::custom)?;
        // The retained buffer is a suffix of the global enqueue sequence.
        // Compaction may shorten it, so equality is not required.
        if snapshot.enqueue_count < retained {
            return Err(D::Error::custom("microtask enqueue count precedes buffer"));
        }

        Ok(Self {
            tasks: snapshot.tasks.into(),
            cursor: snapshot.cursor,
            enqueue_count: snapshot.enqueue_count,
            witness: snapshot.witness.into(),
        })
    }
}

impl<'de> Deserialize<'de> for MacrotaskQueue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename = "MacrotaskQueue")]
        struct Snapshot {
            message_channel_tasks: BinaryHeap<MacrotaskHeapEntry>,
            timer_tasks: BinaryHeap<MacrotaskHeapEntry>,
            io_completion_tasks: BinaryHeap<MacrotaskHeapEntry>,
            next_registration_seq: u64,
        }

        let snapshot = Snapshot::deserialize(deserializer)?;
        let lanes = [
            (
                MacrotaskSource::MessageChannel,
                &snapshot.message_channel_tasks,
            ),
            (MacrotaskSource::Timer, &snapshot.timer_tasks),
            (MacrotaskSource::IoCompletion, &snapshot.io_completion_tasks),
        ];
        let mut registrations = BTreeSet::new();
        let mut label_bytes = 0u64;
        for (source, lane) in lanes {
            for entry in lane.iter() {
                let task = &entry.task;
                // A heap's container, not the task's source field, determines
                // scheduling priority. Refuse source/lane disagreement.
                if task.source != source {
                    return Err(D::Error::custom(
                        "macrotask source does not match queue lane",
                    ));
                }
                if task.registration_seq >= snapshot.next_registration_seq {
                    return Err(D::Error::custom(
                        "macrotask registration is not below next sequence",
                    ));
                }
                // Registration IDs are global across every lane: cancellation
                // and replay must never identify two tasks with one ID.
                if !registrations.insert(task.registration_seq) {
                    return Err(D::Error::custom(
                        "duplicate macrotask registration sequence",
                    ));
                }
                label_bytes =
                    label_bytes.saturating_add(super::estimate_label_memory_bytes(&task.label));
            }
        }

        Ok(Self {
            message_channel_tasks: snapshot.message_channel_tasks,
            timer_tasks: snapshot.timer_tasks,
            io_completion_tasks: snapshot.io_completion_tasks,
            next_registration_seq: snapshot.next_registration_seq,
            label_bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::{EventLoop, Microtask, PromiseHandle, PromiseState, PromiseStore};
    use super::*;
    use crate::closure_model::ClosureHandle;
    use crate::ifc_artifacts::Label;
    use crate::object_model::JsValue;
    use serde_json::{Value, json};

    fn promise_store() -> PromiseStore {
        let mut store = PromiseStore::new();
        let mut queue = MicrotaskQueue::new();
        let source = store.create();
        store
            .then(source, None, None, Label::Secret, &mut queue)
            .unwrap();
        store
    }

    #[test]
    fn promise_restore_preserves_identity_labels_and_settlement_continuation() {
        let mut original = promise_store();
        let snapshot = serde_json::to_value(&original).unwrap();
        let mut restored: PromiseStore = serde_json::from_value(snapshot.clone()).unwrap();
        assert_eq!(serde_json::to_value(&restored).unwrap(), snapshot);
        let mut expected_jobs = MicrotaskQueue::new();
        let mut restored_jobs = MicrotaskQueue::new();
        for (store, queue) in [
            (&mut original, &mut expected_jobs),
            (&mut restored, &mut restored_jobs),
        ] {
            store
                .fulfill(PromiseHandle(0), JsValue::Int(42), Label::Internal, queue)
                .unwrap();
            assert_eq!(store.create(), PromiseHandle(2));
        }
        assert_eq!(expected_jobs.dequeue(), restored_jobs.dequeue());
        assert_eq!(
            serde_json::to_value(&restored).unwrap(),
            serde_json::to_value(&original).unwrap()
        );
        assert_eq!(
            restored.estimated_memory_bytes(),
            restored.estimated_memory_bytes_by_walk()
        );
    }

    #[test]
    fn promise_restore_rejects_handle_aliases_and_creation_sequence_rewrites() {
        let snapshot = serde_json::to_value(promise_store()).unwrap();
        for (field, values) in [
            ("handle", vec![0, 2, u64::from(u32::MAX)]),
            ("creation_seq", vec![0, 2, u64::MAX]),
        ] {
            for value in values {
                let mut invalid = snapshot.clone();
                invalid["promises"][1][field] = json!(value);
                assert!(
                    serde_json::from_value::<PromiseStore>(invalid).is_err(),
                    "accepted rewritten {field}={value} in promise slot 1"
                );
            }
        }
    }

    #[test]
    fn promise_restore_rejects_creation_frontier_rollback_and_overflow() {
        let snapshot = serde_json::to_value(promise_store()).unwrap();
        for next_seq in [0, 1, 3, u64::MAX] {
            let mut invalid = snapshot.clone();
            invalid["next_seq"] = json!(next_seq);
            assert!(
                serde_json::from_value::<PromiseStore>(invalid).is_err(),
                "accepted inconsistent creation frontier {next_seq}"
            );
        }
    }

    #[test]
    fn promise_restore_rejects_settled_records_with_undelivered_reactions() {
        let snapshot = serde_json::to_value(promise_store()).unwrap();
        for state in [
            PromiseState::Fulfilled(JsValue::Int(1)),
            PromiseState::Rejected(JsValue::Int(2)),
        ] {
            let mut invalid = snapshot.clone();
            invalid["promises"][0]["state"] = serde_json::to_value(state).unwrap();
            assert!(serde_json::from_value::<PromiseStore>(invalid).is_err());
        }
    }

    fn job(id: u32) -> Microtask {
        Microtask::PromiseReaction {
            handler: None,
            argument: JsValue::Str("retained payload".into()),
            result_promise: PromiseHandle(id),
            label: Label::Secret,
        }
    }

    fn populated() -> MicrotaskQueue {
        let mut queue = MicrotaskQueue::new();
        for id in 0..3 {
            queue.enqueue(job(id));
        }
        queue
    }

    fn restore(queue: &MicrotaskQueue) -> MicrotaskQueue {
        let encoded = serde_json::to_value(queue).unwrap();
        let restored: MicrotaskQueue = serde_json::from_value(encoded.clone()).unwrap();
        assert_eq!(serde_json::to_value(&restored).unwrap(), encoded);
        assert_eq!(restored.pending_count(), queue.pending_count());
        assert_eq!(
            restored.estimated_memory_bytes(),
            queue.estimated_memory_bytes()
        );
        restored
    }

    fn assert_same_continuation(mut original: MicrotaskQueue) {
        let mut restored = restore(&original);
        original.enqueue(job(9));
        restored.enqueue(job(9));
        while let Some(expected) = original.dequeue() {
            assert_eq!(restored.dequeue(), Some(expected));
        }
        assert_eq!(restored.dequeue(), None);
        assert!(restored.is_empty());
        assert_eq!(restored.witness_log(), original.witness_log());
        original.compact();
        restored.compact();
        assert_eq!(
            serde_json::to_value(&restored).unwrap(),
            serde_json::to_value(&original).unwrap()
        );
    }

    #[test]
    fn empty_and_populated_snapshots_preserve_fifo_and_witnesses() {
        assert_same_continuation(MicrotaskQueue::new());
        assert_same_continuation(populated());
    }

    #[test]
    fn partially_drained_snapshot_preserves_the_read_frontier() {
        let mut queue = populated();
        assert_eq!(queue.dequeue(), Some(job(0)));
        assert_same_continuation(queue);
    }

    #[test]
    fn fully_drained_uncompacted_snapshot_remains_restorable() {
        let mut queue = populated();
        while queue.dequeue().is_some() {}
        assert_same_continuation(queue);
    }

    #[test]
    fn compacted_snapshot_preserves_global_enqueue_ids() {
        let mut queue = populated();
        assert_eq!(queue.dequeue(), Some(job(0)));
        queue.compact();
        // The counter is global, not the length of the compacted buffer.
        assert_eq!(queue.total_enqueued(), 3);
        assert_same_continuation(queue);
    }

    #[test]
    fn restore_rejects_cursor_past_the_buffer() {
        for cursor in [4, usize::MAX] {
            let mut encoded = serde_json::to_value(populated()).unwrap();
            encoded["cursor"] = json!(cursor);
            let error = serde_json::from_value::<MicrotaskQueue>(encoded).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("microtask cursor exceeds buffer length")
            );
        }
    }

    #[test]
    fn restore_rejects_counter_that_would_underflow_dequeue_identity() {
        for count in 0..3u64 {
            let mut encoded = serde_json::to_value(populated()).unwrap();
            encoded["enqueue_count"] = json!(count);
            let error = serde_json::from_value::<MicrotaskQueue>(encoded).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("microtask enqueue count precedes buffer")
            );
        }
    }

    #[test]
    fn event_loop_restore_propagates_invalid_queue_rejection() {
        let mut event_loop = EventLoop::new();
        event_loop.microtasks.enqueue(job(0));
        let mut encoded = serde_json::to_value(event_loop).unwrap();
        encoded["microtasks"]["cursor"] = json!(2);
        assert!(serde_json::from_value::<EventLoop>(encoded).is_err());
    }

    #[test]
    fn missing_required_microtask_fields_still_fail_closed() {
        for field in ["tasks", "cursor", "enqueue_count", "witness"] {
            let mut encoded: Value = serde_json::to_value(populated()).unwrap();
            encoded.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<MicrotaskQueue>(encoded).is_err());
        }
    }

    fn macrotask_populated() -> MacrotaskQueue {
        let mut queue = MacrotaskQueue::new();
        queue.schedule(
            MacrotaskSource::MessageChannel,
            ClosureHandle(1),
            10,
            Label::Public,
        );
        queue.schedule(MacrotaskSource::Timer, ClosureHandle(2), 0, Label::Secret);
        queue.schedule(
            MacrotaskSource::IoCompletion,
            ClosureHandle(3),
            10,
            Label::Confidential,
        );
        queue
    }

    fn assert_same_macrotask_continuation(mut original: MacrotaskQueue) {
        let encoded = serde_json::to_value(&original).unwrap();
        let mut restored: MacrotaskQueue = serde_json::from_value(encoded.clone()).unwrap();
        assert_eq!(serde_json::to_value(&restored).unwrap(), encoded);
        assert_eq!(
            restored.estimated_memory_bytes(),
            original.estimated_memory_bytes()
        );
        assert_eq!(
            restored.schedule(
                MacrotaskSource::Timer,
                ClosureHandle(9),
                10,
                Label::Internal
            ),
            original.schedule(
                MacrotaskSource::Timer,
                ClosureHandle(9),
                10,
                Label::Internal
            )
        );
        for now in [0, 9, 10, u64::MAX] {
            while let Some(expected) = original.dequeue_ready(now) {
                assert_eq!(restored.dequeue_ready(now), Some(expected));
            }
            assert!(restored.dequeue_ready(now).is_none());
        }
        assert!(restored.is_empty());
        assert_eq!(
            serde_json::to_value(&restored).unwrap(),
            serde_json::to_value(&original).unwrap()
        );
    }

    fn assert_macrotask_rejected(encoded: Value, message: &str) {
        let error = serde_json::from_value::<MacrotaskQueue>(encoded).unwrap_err();
        assert!(error.to_string().contains(message), "{error}");
    }

    #[test]
    fn macrotask_empty_and_populated_snapshots_preserve_priority_and_registration() {
        assert_same_macrotask_continuation(MacrotaskQueue::new());
        assert_same_macrotask_continuation(macrotask_populated());
    }

    #[test]
    fn macrotask_restore_accepts_registration_gaps_after_execution() {
        let mut queue = macrotask_populated();
        assert!(queue.dequeue_ready(0).is_some());
        assert_same_macrotask_continuation(queue);
    }

    #[test]
    fn macrotask_restore_accepts_empty_queue_with_nonzero_registration_frontier() {
        let mut queue = macrotask_populated();
        while queue.dequeue_ready(u64::MAX).is_some() {}
        assert_same_macrotask_continuation(queue);
    }

    #[test]
    fn macrotask_restore_rejects_task_in_the_wrong_source_lane() {
        let mut encoded = serde_json::to_value(macrotask_populated()).unwrap();
        let timer = encoded["timer_tasks"]
            .as_array_mut()
            .unwrap()
            .pop()
            .unwrap();
        encoded["message_channel_tasks"]
            .as_array_mut()
            .unwrap()
            .push(timer);
        assert_macrotask_rejected(encoded, "macrotask source does not match queue lane");
    }

    #[test]
    fn macrotask_restore_rejects_duplicate_registration_across_lanes() {
        let mut encoded = serde_json::to_value(macrotask_populated()).unwrap();
        let timer_seq = encoded["timer_tasks"][0]["task"]["registration_seq"].clone();
        encoded["io_completion_tasks"][0]["task"]["registration_seq"] = timer_seq;
        assert_macrotask_rejected(encoded, "duplicate macrotask registration sequence");
    }

    #[test]
    fn macrotask_restore_rejects_duplicate_registration_within_a_lane() {
        let mut encoded = serde_json::to_value(macrotask_populated()).unwrap();
        let timer = encoded["timer_tasks"][0].clone();
        encoded["timer_tasks"].as_array_mut().unwrap().push(timer);
        assert_macrotask_rejected(encoded, "duplicate macrotask registration sequence");
    }

    #[test]
    fn macrotask_restore_rejects_registration_at_or_beyond_the_frontier() {
        let original = serde_json::to_value(macrotask_populated()).unwrap();
        let next = original["next_registration_seq"].as_u64().unwrap();
        for seq in [next, next + 1, u64::MAX] {
            let mut encoded = original.clone();
            encoded["timer_tasks"][0]["task"]["registration_seq"] = json!(seq);
            assert_macrotask_rejected(encoded, "macrotask registration is not below next sequence");
        }
    }

    #[test]
    fn macrotask_restore_rejects_registration_frontier_rollback() {
        let mut encoded = serde_json::to_value(macrotask_populated()).unwrap();
        encoded["next_registration_seq"] = json!(0);
        assert_macrotask_rejected(encoded, "macrotask registration is not below next sequence");
    }

    #[test]
    fn macrotask_event_loop_restore_propagates_invalid_macrotask_rejection() {
        let mut event_loop = EventLoop::new();
        event_loop.macrotasks = macrotask_populated();
        let mut encoded = serde_json::to_value(event_loop).unwrap();
        encoded["macrotasks"]["timer_tasks"][0]["task"]["source"] = json!("MessageChannel");
        assert!(serde_json::from_value::<EventLoop>(encoded).is_err());
    }
}
