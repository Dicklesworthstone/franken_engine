//! Exercise the real Promise stores in both runtime crates, not a model or mock.
//! Registration before/after settlement must preserve the same joined IFC label.

macro_rules! promise_label_conformance {
    ($module:ident, $runtime:ident) => {
        mod $module {
            use $runtime::closure_model::ClosureHandle;
            use $runtime::ifc_artifacts::Label;
            use $runtime::object_model::JsValue;
            use $runtime::promise_model::{
                Microtask, MicrotaskQueue, PromiseHandle, PromiseState, PromiseStore,
            };

            #[derive(Clone, Copy, Debug)]
            enum Registration {
                Then(Option<ClosureHandle>),
                Await,
            }

            fn labels() -> Vec<Label> {
                let mut labels = Label::all_builtin().to_vec();
                labels.extend([
                    Label::Custom { name: "alpha".into(), level: 3 },
                    Label::Custom { name: "zeta-longer-name".into(), level: 3 },
                    Label::Custom { name: "above-builtins".into(), level: 7 },
                ]);
                labels
            }

            fn observe(
                settled_first: bool,
                registration: Registration,
                rejected: bool,
                registration_label: &Label,
                settlement_label: &Label,
            ) -> Microtask {
                let mut store = PromiseStore::new();
                let mut queue = MicrotaskQueue::new();
                let source = store.create();
                let settle = |store: &mut PromiseStore, queue: &mut MicrotaskQueue| {
                    if rejected {
                        store.reject(source, JsValue::Int(42), settlement_label.clone(), queue)
                    } else {
                        store.fulfill(source, JsValue::Int(42), settlement_label.clone(), queue)
                    }.expect("first settlement succeeds");
                };
                if settled_first {
                    settle(&mut store, &mut queue);
                }
                let result = match registration {
                    Registration::Then(handler) => store.then(
                        source,
                        if rejected { None } else { handler },
                        if rejected { handler } else { None },
                        registration_label.clone(),
                        &mut queue,
                    ),
                    Registration::Await => store.then_for_await(
                        source, registration_label.clone(), &mut queue,
                    ),
                }.expect("valid source accepts a reaction");
                if !settled_first {
                    assert_eq!(queue.pending_count(), 0);
                    settle(&mut store, &mut queue);
                }
                assert_eq!(store.get(source).unwrap().label, *settlement_label);
                assert_eq!(store.get(result).unwrap().state, PromiseState::Pending);
                assert_eq!(queue.pending_count(), 1);
                let task = queue.dequeue().expect("one reaction is queued");
                assert!(queue.dequeue().is_none());
                let expected_label = registration_label.join(settlement_label);
                match (&task, registration, rejected) {
                    (Microtask::PromiseReaction { handler, argument, result_promise, label },
                     Registration::Then(expected_handler), false) => {
                        assert_eq!(*handler, expected_handler);
                        assert_eq!(*argument, JsValue::Int(42));
                        assert_eq!(*result_promise, result);
                        assert_eq!(*label, expected_label);
                    }
                    (Microtask::PromiseReaction { handler, argument, result_promise, label },
                     Registration::Then(Some(expected_handler)), true) => {
                        assert_eq!(*handler, Some(expected_handler));
                        assert_eq!(*argument, JsValue::Int(42));
                        assert_eq!(*result_promise, result);
                        assert_eq!(*label, expected_label);
                    }
                    (Microtask::PromiseReaction { handler, argument, result_promise, label },
                     Registration::Await, false) => {
                        assert!(handler.is_none());
                        assert_eq!(*argument, JsValue::Int(42));
                        assert_eq!(*result_promise, result);
                        assert_eq!(*label, expected_label);
                    }
                    (Microtask::PromiseRejection { reason, result_promise, label },
                     Registration::Then(None) | Registration::Await, true) => {
                        assert_eq!(*reason, JsValue::Int(42));
                        assert_eq!(*result_promise, result);
                        assert_eq!(*label, expected_label);
                    }
                    _ => panic!("wrong reaction kind: {task:?} for {registration:?}, rejected={rejected}"),
                }
                task
            }

            fn check_all_labels(registration: Registration, rejected: bool) {
                for registration_label in labels() {
                    for settlement_label in labels() {
                        let early = observe(false, registration, rejected, &registration_label, &settlement_label);
                        let late = observe(true, registration, rejected, &registration_label, &settlement_label);
                        assert_eq!(early, late, "timing changed the reaction's meaning");
                    }
                }
            }

            #[test]
            fn explicit_fulfillment_preserves_both_labels() {
                check_all_labels(Registration::Then(Some(ClosureHandle(7))), false);
            }

            #[test]
            fn implicit_identity_preserves_both_labels() {
                check_all_labels(Registration::Then(None), false);
            }

            #[test]
            fn explicit_rejection_preserves_both_labels() {
                check_all_labels(Registration::Then(Some(ClosureHandle(7))), true);
            }

            #[test]
            fn implicit_thrower_preserves_both_labels() {
                check_all_labels(Registration::Then(None), true);
            }

            #[test]
            fn await_fulfillment_preserves_both_labels() {
                check_all_labels(Registration::Await, false);
            }

            #[test]
            fn await_rejection_preserves_both_labels() {
                check_all_labels(Registration::Await, true);
            }

            #[test]
            fn observers_do_not_taint_unrelated_siblings() {
                let mut store = PromiseStore::new();
                let mut queue = MicrotaskQueue::new();
                let source = store.create();
                let secret_child = store.then(source, None, None, Label::Secret, &mut queue).unwrap();
                let public_child = store.then(source, None, None, Label::Public, &mut queue).unwrap();
                store.fulfill(source, JsValue::Int(42), Label::Public, &mut queue).unwrap();
                for (expected_child, expected_label) in [
                    (secret_child, Label::Secret), (public_child, Label::Public),
                ] {
                    match queue.dequeue().unwrap() {
                        Microtask::PromiseReaction { result_promise, label, .. } => {
                            assert_eq!(result_promise, expected_child);
                            assert_eq!(label, expected_label);
                        }
                        other => panic!("expected fulfillment, got {other:?}"),
                    }
                }
                assert_eq!(store.get(source).unwrap().label, Label::Public);
                assert!(queue.is_empty());
            }

            #[test]
            fn implicit_rejection_chain_keeps_secret_and_transfers_handling() {
                let mut store = PromiseStore::new();
                let mut queue = MicrotaskQueue::new();
                let source = store.reject_with(JsValue::Int(42), Label::Secret, &mut queue);
                let middle = store.then(source, None, None, Label::Public, &mut queue).unwrap();
                let leaf = store.then(middle, None, None, Label::Internal, &mut queue).unwrap();
                for expected_target in [middle, leaf] {
                    match queue.dequeue().unwrap() {
                        Microtask::PromiseRejection { reason, result_promise, label } => {
                            assert_eq!(result_promise, expected_target);
                            assert_eq!(label, Label::Secret);
                            store.reject(result_promise, reason, label, &mut queue).unwrap();
                        }
                        other => panic!("implicit thrower did not propagate: {other:?}"),
                    }
                }
                assert_eq!(store.unhandled_rejections(), vec![leaf]);
                assert_eq!(store.get(leaf).unwrap().state, PromiseState::Rejected(JsValue::Int(42)));
                assert_eq!(store.get(leaf).unwrap().label, Label::Secret);
                assert!(queue.is_empty());
            }

            #[test]
            fn invalid_source_does_not_allocate_a_result_promise() {
                let mut store = PromiseStore::new();
                let mut queue = MicrotaskQueue::new();
                assert!(store.then(PromiseHandle(99), None, None, Label::Secret, &mut queue).is_err());
                assert!(store.then_for_await(PromiseHandle(99), Label::Secret, &mut queue).is_err());
                assert_eq!(store.len(), 0);
                assert!(store.witness_log().is_empty());
                assert!(queue.is_empty());
                assert!(queue.witness_log().is_empty());
            }
        }
    };
}

promise_label_conformance!(engine, frankenengine_engine);
promise_label_conformance!(core, frankenengine_core);
