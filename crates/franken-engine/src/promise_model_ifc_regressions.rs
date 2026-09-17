//! Security regressions for Promise label propagation and admission estimates.

use super::*;

#[derive(Clone, Copy, Debug)]
enum Registration {
    Identity,
    Handler,
    Await,
}

fn labels() -> Vec<Label> {
    let mut result = Label::all_builtin().to_vec();
    result.extend([
        Label::Custom {
            name: "a".repeat(4096),
            level: 3,
        },
        Label::Custom {
            name: "z".into(),
            level: 3,
        },
        Label::Custom {
            name: "tenant-secret".repeat(64),
            level: 9,
        },
        Label::Custom {
            name: String::new(),
            level: 10,
        },
    ]);
    result
}

fn register(
    store: &mut PromiseStore,
    source: PromiseHandle,
    label: Label,
    queue: &mut MicrotaskQueue,
    registration: Registration,
) -> PromiseHandle {
    match registration {
        Registration::Identity => store.then(source, None, None, label, queue),
        Registration::Handler => store.then(
            source,
            Some(ClosureHandle(11)),
            Some(ClosureHandle(12)),
            label,
            queue,
        ),
        Registration::Await => store.then_for_await(source, label, queue),
    }
    .expect("source handle is valid")
}

fn settle(
    store: &mut PromiseStore,
    source: PromiseHandle,
    rejected: bool,
    label: Label,
    queue: &mut MicrotaskQueue,
) {
    let payload = JsValue::Str("sensitive-payload".into());
    if rejected {
        store.reject(source, payload, label, queue)
    } else {
        store.fulfill(source, payload, label, queue)
    }
    .expect("source is pending");
}

fn reaction_label(task: &Microtask) -> &Label {
    match task {
        Microtask::PromiseReaction { label, .. }
        | Microtask::PromiseRejection { label, .. }
        | Microtask::ResolveThenable { label, .. } => label,
    }
}

fn registration_result(
    source_label: &Label,
    context_label: &Label,
    rejected: bool,
    settled_first: bool,
    registration: Registration,
) -> Microtask {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let source = store.create();
    let result;
    if settled_first {
        settle(&mut store, source, rejected, source_label.clone(), &mut queue);
        let projection = store
            .projected_then_memory_bytes(source, context_label, &queue)
            .expect("valid settled source");
        result = register(
            &mut store,
            source,
            context_label.clone(),
            &mut queue,
            registration,
        );
        assert_eq!(
            projection,
            (store.estimated_memory_bytes(), queue.estimated_memory_bytes()),
            "settled-registration preflight: {registration:?}, {source_label:?}, {context_label:?}"
        );
    } else {
        let projection = store
            .projected_then_memory_bytes(source, context_label, &queue)
            .expect("valid pending source");
        result = register(
            &mut store,
            source,
            context_label.clone(),
            &mut queue,
            registration,
        );
        assert_eq!(
            projection,
            (store.estimated_memory_bytes(), queue.estimated_memory_bytes())
        );
        let payload = JsValue::Str("sensitive-payload".into());
        let projection = if rejected {
            store.projected_reject_memory_bytes(source, &payload, source_label, &queue)
        } else {
            store.projected_fulfill_memory_bytes(source, &payload, source_label, &queue)
        }
        .expect("valid pending source");
        settle(&mut store, source, rejected, source_label.clone(), &mut queue);
        assert_eq!(
            projection,
            (store.estimated_memory_bytes(), queue.estimated_memory_bytes()),
            "settlement preflight: {registration:?}, {source_label:?}, {context_label:?}"
        );
    }
    assert_eq!(store.get(source).unwrap().label, *source_label);
    if rejected {
        assert!(store.get(source).unwrap().rejection_handled);
    }
    let task = queue.dequeue().expect("one reaction is scheduled");
    assert_eq!(reaction_label(&task), &source_label.join(context_label));
    match &task {
        Microtask::PromiseReaction { result_promise, .. }
        | Microtask::PromiseRejection { result_promise, .. } => {
            assert_eq!(*result_promise, result);
        }
        Microtask::ResolveThenable { .. } => panic!("not a thenable-resolution job"),
    }
    assert!(queue.is_empty());
    task
}

#[test]
fn labels_and_payloads_do_not_depend_on_registration_timing() {
    let labels = labels();
    for source in &labels {
        for context in &labels {
            for rejected in [false, true] {
                for registration in [
                    Registration::Identity,
                    Registration::Handler,
                    Registration::Await,
                ] {
                    let before = registration_result(source, context, rejected, false, registration);
                    let after = registration_result(source, context, rejected, true, registration);
                    assert_eq!(before, after);
                }
            }
        }
    }
}

#[test]
fn joined_label_preflight_matches_clone_without_allocating_a_join() {
    let mut labels = labels();
    labels.push(Label::Custom {
        name: String::with_capacity(1024),
        level: 10,
    });
    for left in &labels {
        for right in &labels {
            assert_eq!(
                estimate_joined_label_memory_bytes(left, right),
                estimate_label_memory_bytes(&left.join(right)),
                "{left:?} joined with {right:?}"
            );
        }
    }
}

#[test]
fn pending_fanout_preflight_accounts_for_each_reaction_label() {
    for rejected in [false, true] {
        let mut store = PromiseStore::new();
        let mut queue = MicrotaskQueue::new();
        let source = store.create();
        let contexts = labels();
        for context in &contexts {
            register(
                &mut store,
                source,
                context.clone(),
                &mut queue,
                Registration::Identity,
            );
        }
        let label = Label::Confidential;
        let payload = JsValue::Str("sensitive-payload".into());
        let before_store = serde_json::to_vec(&store).unwrap();
        let before_queue = serde_json::to_vec(&queue).unwrap();
        let projection = if rejected {
            store.projected_reject_memory_bytes(source, &payload, &label, &queue)
        } else {
            store.projected_fulfill_memory_bytes(source, &payload, &label, &queue)
        }
        .unwrap();
        assert_eq!(before_store, serde_json::to_vec(&store).unwrap());
        assert_eq!(before_queue, serde_json::to_vec(&queue).unwrap());
        settle(&mut store, source, rejected, label.clone(), &mut queue);
        assert_eq!(
            projection,
            (store.estimated_memory_bytes(), queue.estimated_memory_bytes())
        );
        for context in contexts {
            assert_eq!(
                reaction_label(&queue.dequeue().unwrap()),
                &label.join(&context)
            );
        }
        assert!(queue.is_empty());
    }
}

#[test]
fn native_adoption_preserves_both_source_and_registration_labels() {
    for rejected in [false, true] {
        for (source_label, context_label) in [
            (Label::Secret, Label::Public),
            (Label::Public, Label::Secret),
        ] {
            let mut store = PromiseStore::new();
            let mut queue = MicrotaskQueue::new();
            let source = store.create();
            let target = store.create();
            store
                .register_native_adoption(source, target, context_label.clone())
                .unwrap();
            settle(&mut store, source, rejected, source_label.clone(), &mut queue);
            let task = queue.dequeue().unwrap();
            assert_eq!(reaction_label(&task), &source_label.join(&context_label));
            match task {
                Microtask::PromiseReaction { result_promise, .. }
                | Microtask::PromiseRejection { result_promise, .. } => {
                    assert_eq!(result_promise, target);
                }
                Microtask::ResolveThenable { .. } => panic!("unexpected job kind"),
            }
        }
    }
}

#[test]
fn implicit_identity_and_thrower_keep_secrets_across_multiple_hops() {
    for rejected in [false, true] {
        let mut store = PromiseStore::new();
        let mut queue = MicrotaskQueue::new();
        let source = store.create();
        settle(&mut store, source, rejected, Label::Secret, &mut queue);
        let first = store
            .then(source, None, None, Label::Public, &mut queue)
            .unwrap();
        let second = store
            .then(first, None, None, Label::Public, &mut queue)
            .unwrap();
        for _ in 0..2 {
            let task = queue.dequeue().expect("forwarding job");
            assert_eq!(reaction_label(&task), &Label::Secret);
            match task {
                Microtask::PromiseReaction {
                    handler: None,
                    argument,
                    result_promise,
                    label,
                } => store
                    .fulfill(result_promise, argument, label, &mut queue)
                    .unwrap(),
                Microtask::PromiseRejection {
                    reason,
                    result_promise,
                    label,
                } => {
                    store
                        .reject(result_promise, reason, label, &mut queue)
                        .unwrap();
                }
                _ => panic!("expected an implicit identity or thrower"),
            }
        }
        assert_eq!(store.get(second).unwrap().label, Label::Secret);
        assert_eq!(store.get(second).unwrap().state.is_rejected(), rejected);
        assert!(!store.get(second).unwrap().label.can_flow_to(&Label::Public));
        assert!(queue.is_empty());
    }
}
