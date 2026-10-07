//! Fail-closed reconstruction of deterministic task queues.
//!
//! Serialized queue fields form one state machine; individually well-typed
//! fields are not enough. Validate their relationships before exposing a
//! restored queue to scheduling, compaction, or memory accounting. This does
//! not authenticate snapshots or replace the caller's decode-size budget.

use std::collections::{BTreeSet, BinaryHeap};

use serde::de::Error as _;
use serde::{Deserialize, Deserializer};

use super::{
    MacrotaskHeapEntry, MacrotaskQueue, MacrotaskSource, Microtask, MicrotaskQueue, WitnessEvent,
};

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
            tasks: snapshot.tasks,
            cursor: snapshot.cursor,
            enqueue_count: snapshot.enqueue_count,
            witness: snapshot.witness,
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
            }
        }

        Ok(Self {
            message_channel_tasks: snapshot.message_channel_tasks,
            timer_tasks: snapshot.timer_tasks,
            io_completion_tasks: snapshot.io_completion_tasks,
            next_registration_seq: snapshot.next_registration_seq,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::{EventLoop, Microtask, PromiseHandle};
    use super::*;
    use crate::closure_model::ClosureHandle;
    use crate::ifc_artifacts::Label;
    use crate::object_model::JsValue;
    use serde_json::{Value, json};

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
