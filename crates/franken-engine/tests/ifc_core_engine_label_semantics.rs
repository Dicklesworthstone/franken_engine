#![forbid(unsafe_code)]

// Each contract is instantiated against both actual runtime crates.
macro_rules! label_contract {
    ($module:ident, $runtime:ident) => {
        mod $module {
            use $runtime::ifc_artifacts::{
                FlowCheckResult, FlowPolicy, FlowRule, IfcSchemaVersion, Ir2LabelSource, Label,
            };
            use $runtime::signature_preimage::{SIGNATURE_SENTINEL, Signature};

            fn labels() -> Vec<Label> {
                let mut values = Label::all_builtin().to_vec();
                for level in [0, 1, 2, 3, 4, u32::MAX] {
                    for name in ["alpha", "omega"] {
                        values.push(Label::Custom {
                            name: name.to_string(),
                            level,
                        });
                    }
                }
                values
            }

            #[test]
            fn pair_algebra_respects_exact_order_and_sensitivity() {
                for a in labels() {
                    for b in labels() {
                        let join = a.join(&b);
                        let meet = a.meet(&b);
                        assert_eq!(join, b.join(&a), "join({a}, {b})");
                        assert_eq!(meet, b.meet(&a), "meet({a}, {b})");
                        assert!(join >= a && join >= b);
                        assert!(meet <= a && meet <= b);
                        assert_eq!(join.level(), a.level().max(b.level()));
                        assert_eq!(meet.level(), a.level().min(b.level()));
                        assert_eq!(a.join(&a), a);
                        assert_eq!(a.meet(&a), a);
                        assert_eq!(a.join(&a.meet(&b)), a);
                        assert_eq!(a.meet(&a.join(&b)), a);
                        assert_eq!(a.can_flow_to(&b), a.level() <= b.level());
                    }
                }
            }

            #[test]
            fn reductions_are_associative_and_operand_order_independent() {
                let values = labels();
                for a in &values {
                    for b in &values {
                        for c in &values {
                            assert_eq!(a.join(&b.join(c)), a.join(b).join(c));
                            assert_eq!(a.meet(&b.meet(c)), a.meet(b).meet(c));
                            let forward = [a.clone(), b.clone(), c.clone()];
                            let reverse = [c.clone(), b.clone(), a.clone()];
                            assert_eq!(
                                Label::join_all(forward.clone()),
                                Label::join_all(reverse.clone())
                            );
                            assert_eq!(Label::meet_all(forward), Label::meet_all(reverse));
                        }
                    }
                }
                assert_eq!(Label::join_all([]), None);
                assert_eq!(Label::meet_all([]), None);
            }

            #[test]
            fn computed_taint_and_serialization_do_not_depend_on_operand_order() {
                let custom = Label::Custom {
                    name: "credential-origin".to_string(),
                    level: 3,
                };
                for input_labels in [
                    vec![Label::Secret, custom.clone()],
                    vec![custom.clone(), Label::Secret],
                    vec![Label::Public, Label::Secret, custom.clone(), custom.clone()],
                ] {
                    let computed = Ir2LabelSource::Computed { input_labels }.assign_label();
                    assert_eq!(computed, custom);
                    assert_eq!(
                        serde_json::to_vec(&computed).unwrap(),
                        serde_json::to_vec(&custom).unwrap()
                    );
                }
                assert_eq!(
                    Ir2LabelSource::Computed {
                        input_labels: vec![]
                    }
                    .assign_label(),
                    Label::Public
                );
            }

            #[test]
            fn operand_swap_cannot_evade_the_selected_exact_label_prohibition() {
                let alpha = Label::Custom {
                    name: "alpha".into(),
                    level: 0,
                };
                let omega = Label::Custom {
                    name: "omega".into(),
                    level: 0,
                };
                let policy = FlowPolicy {
                    policy_id: "operand-policy".into(),
                    extension_id: "operand-extension".into(),
                    label_classes: [alpha.clone(), omega.clone(), Label::Public].into(),
                    clearance_classes: [Label::Public].into(),
                    allowed_flows: vec![FlowRule {
                        source_label: alpha.clone(),
                        sink_clearance: Label::Public,
                    }],
                    prohibited_flows: vec![FlowRule {
                        source_label: omega.clone(),
                        sink_clearance: Label::Public,
                    }],
                    declassification_routes: vec![],
                    epoch_id: 1,
                    schema_version: IfcSchemaVersion::CURRENT,
                    signature: Signature::from_bytes(SIGNATURE_SENTINEL),
                };
                // This exercises the policy predicate, not signature admission.
                assert_eq!(
                    policy.is_flow_allowed(&alpha, &Label::Public),
                    FlowCheckResult::Allowed
                );
                assert_eq!(
                    policy.is_flow_allowed(&omega, &Label::Public),
                    FlowCheckResult::Prohibited
                );
                for input_labels in [
                    vec![alpha.clone(), omega.clone()],
                    vec![omega.clone(), alpha.clone()],
                    vec![Label::Public, alpha, omega.clone()],
                ] {
                    let computed = Ir2LabelSource::Computed { input_labels }.assign_label();
                    assert_eq!(computed, omega);
                    assert_eq!(
                        policy.is_flow_allowed(&computed, &Label::Public),
                        FlowCheckResult::Prohibited
                    );
                }
            }
        }
    };
}

label_contract!(core_labels, frankenengine_core);
label_contract!(engine_labels, frankenengine_engine);
