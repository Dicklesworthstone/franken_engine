#![forbid(unsafe_code)]

// Each contract is instantiated against both actual runtime crates.
macro_rules! label_contract {
    ($module:ident, $runtime:ident $(, $field:ident: $value:expr)* $(,)?) => {
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
                    $($field: $value,)*
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
label_contract!(
    engine_labels,
    frankenengine_engine,
    enforcement_mode: frankenengine_engine::ifc_artifacts::FlowPolicyEnforcement::AllowlistOnly,
);

macro_rules! envelope_contract {
    ($module:ident, $runtime:ident) => {
        mod $module {
            use $runtime::ifc_artifacts::{
                ClearanceClass, FlowAuthorizationAdvisory, FlowEnvelope, IfcSchemaVersion, Label,
            };

            fn envelope(source: &Label, sink: ClearanceClass, grants: &[&str]) -> FlowEnvelope {
                FlowEnvelope {
                    envelope_id: "envelope".into(),
                    extension_id: "extension".into(),
                    producible_labels: [source.clone()].into(),
                    accessible_clearances: [sink].into(),
                    authorized_declassifications: grants.iter().map(|grant| (*grant).into()).collect(),
                    policy_ref: "policy".into(),
                    epoch_id: 7,
                    schema_version: IfcSchemaVersion::CURRENT,
                }
            }

            #[test]
            fn sealed_sink_gate_uses_sensitivity_not_variant() {
                let sink = ClearanceClass::SealedSink;
                for level in [0, 1, 2, 3, 4, u32::MAX] {
                    let source = Label::Custom {
                        name: "source".into(),
                        level,
                    };
                    let env = envelope(&source, sink, &[]);
                    let assessment = env.assess_flow_authorization(&source, &sink);
                    assert_eq!(assessment.envelope_authorized, level <= 3);
                    assert_eq!(assessment.flow_authorized, level < 3);
                    assert_eq!(env.is_flow_authorized(&source, &sink), level < 3);
                    assert_eq!(assessment.requires_declassification(), level >= 3);
                    assert!(assessment.declassification_obligation.is_none());
                    match level {
                        0..=2 => assert!(assessment.advisories.is_empty()),
                        3 => assert_eq!(
                            assessment.advisories,
                            vec![FlowAuthorizationAdvisory::ExplicitAuthorizationRequired {
                                source_label: source,
                                sink_clearance: sink,
                            }]
                        ),
                        _ => assert_eq!(
                            assessment.advisories,
                            vec![FlowAuthorizationAdvisory::DeclassificationObligationRequired {
                                source_label: source,
                                sink_clearance: sink,
                            }]
                        ),
                    }
                }
            }

            #[test]
            fn built_in_grants_do_not_alias_custom_label_names() {
                let sink = ClearanceClass::SealedSink;
                for name in ["secret", "top_secret", "secret:obligation", "\u{03b1}", ""] {
                    let source = Label::Custom {
                        name: name.into(),
                        level: 3,
                    };
                    let env = envelope(
                        &source,
                        sink,
                        &[
                            "sealed_sink:secret:grant-secret",
                            "sealed_sink:top_secret:grant-top-secret",
                        ],
                    );
                    let assessment = env.assess_flow_authorization(&source, &sink);
                    assert!(!assessment.flow_authorized);
                    assert!(assessment.requires_declassification());
                    assert!(assessment.declassification_obligation.is_none());
                }
            }

            #[test]
            fn concrete_built_in_obligation_is_not_immediate_permission() {
                let sink = ClearanceClass::SealedSink;
                for (source, grant) in [
                    (Label::Secret, "sealed_sink:secret:approval"),
                    (Label::TopSecret, "sealed_sink:top_secret:approval"),
                ] {
                    let env = envelope(&source, sink, &[grant]);
                    let assessment = env.assess_flow_authorization(&source, &sink);
                    assert!(!assessment.flow_authorized);
                    assert!(!env.is_flow_authorized(&source, &sink));
                    assert!(assessment.requires_declassification());
                    assert!(assessment.advisories.is_empty());
                    let obligation = assessment.declassification_obligation.unwrap();
                    assert_eq!(obligation.obligation_id, "approval");
                    assert_eq!(obligation.source_label, source);
                    assert_eq!(obligation.target_clearance, sink);
                    assert_eq!(obligation.approval_authority, "policy");
                    assert_eq!(obligation.expiry_epoch, Some(7));
                }
            }

            #[test]
            fn missing_built_in_authorization_remains_explicitly_pending() {
                let sink = ClearanceClass::SealedSink;
                for source in [Label::Secret, Label::TopSecret] {
                    let env = envelope(&source, sink, &[]);
                    let assessment = env.assess_flow_authorization(&source, &sink);
                    assert_eq!(assessment.envelope_authorized, source == Label::Secret);
                    assert!(!assessment.flow_authorized);
                    assert!(assessment.requires_declassification());
                    assert_eq!(assessment.advisories.len(), 1);
                }
            }

            #[test]
            fn other_sinks_preserve_existing_clearance_permissions() {
                for sink in [
                    ClearanceClass::OpenSink,
                    ClearanceClass::RestrictedSink,
                    ClearanceClass::AuditedSink,
                    ClearanceClass::NeverSink,
                ] {
                    for level in [0, 1, 2, 3, 4, u32::MAX] {
                        let source = Label::Custom {
                            name: "source".into(),
                            level,
                        };
                        let env = envelope(&source, sink, &[]);
                        let assessment = env.assess_flow_authorization(&source, &sink);
                        assert_eq!(assessment.flow_authorized, sink.can_receive(&source));
                        assert!(assessment.advisories.is_empty());
                        assert!(assessment.declassification_obligation.is_none());
                    }
                }
            }

            #[test]
            fn grants_never_bypass_source_or_sink_membership() {
                let sink = ClearanceClass::SealedSink;
                for source in [
                    Label::Secret,
                    Label::Custom {
                        name: "secret".into(),
                        level: 3,
                    },
                ] {
                    for remove_source in [false, true] {
                        let mut env = envelope(&source, sink, &["sealed_sink:secret:approval"]);
                        if remove_source {
                            env.producible_labels.clear();
                        } else {
                            env.accessible_clearances.clear();
                        }
                        let assessment = env.assess_flow_authorization(&source, &sink);
                        assert!(!assessment.envelope_authorized);
                        assert!(!assessment.flow_authorized);
                        assert!(assessment.declassification_obligation.is_none());
                    }
                }
            }
        }
    };
}

envelope_contract!(core_envelopes, frankenengine_core);
envelope_contract!(engine_envelopes, frankenengine_engine);

#[test]
fn core_and_engine_serialize_identical_authorization_assessments() {
    use frankenengine_engine::ifc_artifacts::{ClearanceClass, FlowEnvelope, IfcSchemaVersion, Label};
    let mut sources = Label::all_builtin().to_vec();
    for level in [0, 1, 2, 3, 4, u32::MAX] {
        sources.push(Label::Custom {
            name: "exact-label".into(),
            level,
        });
    }
    for source in sources {
        for with_grants in [false, true] {
            let engine_env = FlowEnvelope {
                envelope_id: "envelope".into(),
                extension_id: "extension".into(),
                producible_labels: [source.clone()].into(),
                accessible_clearances: [ClearanceClass::SealedSink].into(),
                authorized_declassifications: if with_grants {
                    vec![
                        "sealed_sink:secret:approval".into(),
                        "sealed_sink:top_secret:approval".into(),
                    ]
                } else {
                    vec![]
                },
                policy_ref: "policy".into(),
                epoch_id: 7,
                schema_version: IfcSchemaVersion::CURRENT,
            };
            let core_env: frankenengine_core::ifc_artifacts::FlowEnvelope =
                serde_json::from_value(serde_json::to_value(&engine_env).unwrap()).unwrap();
            let core_source: frankenengine_core::ifc_artifacts::Label =
                serde_json::from_value(serde_json::to_value(&source).unwrap()).unwrap();
            let engine = engine_env.assess_flow_authorization(&source, &ClearanceClass::SealedSink);
            let core = core_env.assess_flow_authorization(
                &core_source,
                &frankenengine_core::ifc_artifacts::ClearanceClass::SealedSink,
            );
            assert_eq!(
                serde_json::to_value(engine).unwrap(),
                serde_json::to_value(core).unwrap()
            );
            assert_eq!(
                serde_json::to_vec(&engine_env).unwrap(),
                serde_json::to_vec(&core_env).unwrap()
            );
        }
    }
}
