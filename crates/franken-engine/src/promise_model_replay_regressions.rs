//! Regression coverage for queue compaction, rollback, and checkpoint replay.

use super::*;
use std::collections::VecDeque;

fn task(value: i64) -> Microtask {
    Microtask::PromiseReaction {
        handler: None,
        argument: JsValue::Int(value),
        result_promise: PromiseHandle(0),
        label: Label::Public,
    }
}

fn dequeue_ids(queue: &MicrotaskQueue) -> Vec<u64> {
    queue
        .witness_log()
        .iter()
        .filter_map(|event| match event {
            WitnessEvent::MicrotaskDequeued { index } => Some(*index),
            _ => None,
        })
        .collect()
}

#[test]
fn repeated_full_compaction_never_reuses_a_witness_id() {
    let mut queue = MicrotaskQueue::new();
    for index in 0..128 {
        queue.enqueue(task(index));
        assert_eq!(queue.dequeue(), Some(task(index)));
        queue.compact();
        assert!(queue.is_empty());
    }
    assert_eq!(dequeue_ids(&queue), (0..128).collect::<Vec<_>>());
}

#[test]
fn partial_compaction_preserves_pending_and_new_job_ids() {
    let mut queue = MicrotaskQueue::new();
    for value in 0..4 {
        queue.enqueue(task(value));
    }
    assert_eq!(queue.dequeue(), Some(task(0)));
    queue.compact();
    queue.enqueue(task(4));
    assert_eq!(queue.dequeue(), Some(task(1)));
    assert_eq!(queue.dequeue(), Some(task(2)));
    queue.compact();
    queue.compact();
    assert_eq!(queue.dequeue(), Some(task(3)));
    assert_eq!(queue.dequeue(), Some(task(4)));
    assert_eq!(queue.dequeue(), None);
    assert_eq!(dequeue_ids(&queue), vec![0, 1, 2, 3, 4]);
}

#[test]
fn checkpoint_after_compaction_recovers_ids_without_new_state_fields() {
    let mut queue = MicrotaskQueue::new();
    for value in 0..3 {
        queue.enqueue(task(value));
    }
    queue.dequeue();
    queue.compact();
    let wire = serde_json::to_value(&queue).unwrap();
    let fields = wire.as_object().unwrap();
    assert_eq!(fields.len(), 4);
    for field in ["tasks", "cursor", "enqueue_count", "witness"] {
        assert!(fields.contains_key(field));
    }
    let mut restored: MicrotaskQueue = serde_json::from_value(wire).unwrap();
    queue.enqueue(task(3));
    restored.enqueue(task(3));
    while !queue.is_empty() {
        assert_eq!(queue.dequeue(), restored.dequeue());
    }
    assert_eq!(dequeue_ids(&restored), vec![0, 1, 2, 3]);
    assert_eq!(
        serde_json::to_vec(&queue).unwrap(),
        serde_json::to_vec(&restored).unwrap()
    );
}

#[test]
fn rolled_back_enqueue_does_not_shift_pending_witness_ids() {
    let mut queue = MicrotaskQueue::new();
    queue.enqueue(task(0));
    queue.enqueue(task(1));
    queue.dequeue();
    queue.compact();
    queue.enqueue(task(99));
    assert_eq!(queue.rollback_last_enqueued(), Some(task(99)));
    assert_eq!(queue.total_enqueued(), 2);
    queue.enqueue(task(2));
    assert_eq!(queue.dequeue(), Some(task(1)));
    assert_eq!(queue.dequeue(), Some(task(2)));
    assert_eq!(dequeue_ids(&queue), vec![0, 1, 2]);
}

#[test]
fn mixed_operations_match_an_independent_fifo_id_model() {
    let mut queue = MicrotaskQueue::new();
    let mut expected = VecDeque::new();
    let mut expected_dequeues = Vec::new();
    let mut seed = 0x56a3_129f_0000_0001_u64;
    for step in 0..2000 {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        match (seed >> 32) % 5 {
            0 | 1 => {
                let job = task(step);
                expected.push_back((queue.total_enqueued(), job.clone()));
                queue.enqueue(job);
            }
            2 => {
                if let Some((index, job)) = expected.pop_front() {
                    assert_eq!(queue.dequeue(), Some(job));
                    expected_dequeues.push(index);
                } else {
                    assert_eq!(queue.dequeue(), None);
                }
            }
            3 => queue.compact(),
            _ => {
                queue = serde_json::from_slice(&serde_json::to_vec(&queue).unwrap()).unwrap();
            }
        }
        assert_eq!(queue.pending_count(), expected.len());
        assert_eq!(queue.is_empty(), expected.is_empty());
    }
    while let Some((index, job)) = expected.pop_front() {
        assert_eq!(queue.dequeue(), Some(job));
        expected_dequeues.push(index);
    }
    assert_eq!(dequeue_ids(&queue), expected_dequeues);
}
