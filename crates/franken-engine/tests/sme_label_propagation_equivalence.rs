//! SME / label-propagation equivalence checks for MM.3.
//!
//! These tests cover the terminating finite-trace domain: each generated trace
//! is treated as the shared output trace produced by both strategies, and the
//! assertion compares the observer-visible projections.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use frankenengine_engine::flow_lattice::{Clearance, LabelClass};
use frankenengine_engine::ifc_label_translation_validator::{
    SecurityLabel, faithful_lower, generate_ifc_test_programs, reference_trace, target_trace,
};
use frankenengine_engine::secure_multi_execution_kernel::{
    HostcallInvocation, SecureMultiExecutionKernel, SecurityLevel, SmeHostcallKind,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use proptest::prelude::*;

#[derive(Debug, Clone, PartialEq, Eq)]
struct TraceOutput {
    label: SecurityLevel,
    bytes: Vec<u8>,
}

fn security_level_to_label_class(level: SecurityLevel) -> LabelClass {
    match level {
        SecurityLevel::Public => LabelClass::Public,
        SecurityLevel::Internal => LabelClass::Internal,
        SecurityLevel::Confidential => LabelClass::Confidential,
        SecurityLevel::Secret => LabelClass::Secret,
    }
}

fn security_label_to_security_level(label: SecurityLabel) -> Option<SecurityLevel> {
    match label {
        SecurityLabel::Public => Some(SecurityLevel::Public),
        SecurityLabel::Internal => Some(SecurityLevel::Internal),
        SecurityLabel::Confidential => Some(SecurityLevel::Confidential),
        SecurityLabel::Secret => Some(SecurityLevel::Secret),
        SecurityLabel::TopSecret => None,
    }
}

fn observer_clearance(observer: SecurityLevel) -> Clearance {
    match observer {
        SecurityLevel::Public => Clearance::NeverSink,
        SecurityLevel::Internal => Clearance::RestrictedSink,
        SecurityLevel::Confidential => Clearance::AuditedSink,
        SecurityLevel::Secret => Clearance::SealedSink,
    }
}

fn ifc_reference_trace_for_sme_domain(program_name: &str) -> Vec<TraceOutput> {
    let program = generate_ifc_test_programs()
        .into_iter()
        .find(|program| program.name == program_name)
        .expect("program name should come from the generated IFC corpus");
    let reference = reference_trace(&program.program, &program.trusted);
    let target = target_trace(&faithful_lower(&program.program), &program.trusted);
    assert_eq!(
        reference, target,
        "{} failed faithful lowering",
        program.name
    );

    reference
        .iter()
        .enumerate()
        .filter_map(|(idx, event)| {
            let label = security_label_to_security_level(event.state_after.result_label)?;
            let bytes = format!("{}:{idx}:{:?}", program.name, event.kind).into_bytes();
            Some(TraceOutput { label, bytes })
        })
        .collect()
}

fn label_propagation_visible(observer: SecurityLevel, label: SecurityLevel) -> bool {
    security_level_to_label_class(label).can_flow_to(&observer_clearance(observer))
}

fn label_propagation_visible_trace(
    observer: SecurityLevel,
    trace: &[TraceOutput],
) -> Vec<(SecurityLevel, Vec<u8>)> {
    trace
        .iter()
        .filter(|output| label_propagation_visible(observer, output.label))
        .map(|output| (output.label, output.bytes.clone()))
        .collect()
}

fn sme_visible_trace(
    observer: SecurityLevel,
    trace: &[TraceOutput],
) -> Vec<(SecurityLevel, Vec<u8>)> {
    let mut kernel = SecureMultiExecutionKernel::with_standard_levels(SecurityEpoch::from_raw(39));

    for (idx, output) in trace.iter().enumerate() {
        let invocation_args = (idx as u64).to_be_bytes();
        let invocation = HostcallInvocation::new(
            format!("mm3-trace-{idx}"),
            SmeHostcallKind::PolicyRequest,
            SecurityLevel::Secret,
            &invocation_args,
        );
        kernel
            .deliver_labeled_output(&invocation, output.label, output.bytes.clone())
            .expect("standard SME kernel should deliver direct labeled outputs");
    }

    assert!(kernel.isolation_holds());
    kernel
        .visible_outputs(observer)
        .expect("standard runtime levels include every SME observer")
        .iter()
        .map(|output| (output.label, output.bytes.clone()))
        .collect()
}

fn security_level_strategy() -> impl Strategy<Value = SecurityLevel> {
    prop_oneof![
        Just(SecurityLevel::Public),
        Just(SecurityLevel::Internal),
        Just(SecurityLevel::Confidential),
        Just(SecurityLevel::Secret),
    ]
}

fn trace_output_strategy() -> impl Strategy<Value = TraceOutput> {
    (
        security_level_strategy(),
        proptest::collection::vec(any::<u8>(), 0..64),
    )
        .prop_map(|(label, bytes)| TraceOutput { label, bytes })
}

#[test]
fn per_level_delivery_sets_match_label_propagation_clearances_exhaustively() {
    for output_label in SecurityLevel::all().iter().copied() {
        let mut kernel =
            SecureMultiExecutionKernel::with_standard_levels(SecurityEpoch::from_raw(39));
        let invocation = HostcallInvocation::new(
            format!("mm3-exhaustive-{}", output_label.stable_name()),
            SmeHostcallKind::PolicyRequest,
            SecurityLevel::Secret,
            output_label.stable_name().as_bytes(),
        );
        let receipt = kernel
            .deliver_labeled_output(&invocation, output_label, b"payload".to_vec())
            .expect("standard SME kernel should deliver direct labeled outputs");

        let expected_delivered_to: BTreeSet<_> = SecurityLevel::all()
            .iter()
            .copied()
            .filter(|observer| label_propagation_visible(*observer, output_label))
            .collect();
        let expected_suppressed_from: BTreeSet<_> = SecurityLevel::all()
            .iter()
            .copied()
            .filter(|observer| !label_propagation_visible(*observer, output_label))
            .collect();

        assert_eq!(receipt.delivered_to, expected_delivered_to);
        assert_eq!(receipt.suppressed_from, expected_suppressed_from);
    }
}

#[test]
fn representative_terminating_program_traces_have_same_observations() {
    let programs = [
        (
            "public_metrics_status",
            vec![
                TraceOutput {
                    label: SecurityLevel::Public,
                    bytes: b"tick=1".to_vec(),
                },
                TraceOutput {
                    label: SecurityLevel::Internal,
                    bytes: b"queue_depth=7".to_vec(),
                },
            ],
        ),
        (
            "credential_read_then_policy_audit",
            vec![
                TraceOutput {
                    label: SecurityLevel::Secret,
                    bytes: b"token_hash".to_vec(),
                },
                TraceOutput {
                    label: SecurityLevel::Public,
                    bytes: b"audit_redacted".to_vec(),
                },
            ],
        ),
        (
            "mixed_hostcall_result_stream",
            vec![
                TraceOutput {
                    label: SecurityLevel::Public,
                    bytes: b"clock".to_vec(),
                },
                TraceOutput {
                    label: SecurityLevel::Confidential,
                    bytes: b"session_summary".to_vec(),
                },
                TraceOutput {
                    label: SecurityLevel::Internal,
                    bytes: b"cache_key".to_vec(),
                },
                TraceOutput {
                    label: SecurityLevel::Secret,
                    bytes: b"credential_use".to_vec(),
                },
            ],
        ),
    ];

    for (program, trace) in programs {
        for observer in SecurityLevel::all().iter().copied() {
            assert_eq!(
                sme_visible_trace(observer, &trace),
                label_propagation_visible_trace(observer, &trace),
                "program {program} diverged for observer {observer}"
            );
        }
    }
}

#[test]
fn ifc_corpus_program_traces_have_same_observations_in_sme_v1_domain() {
    let programs = generate_ifc_test_programs();
    assert!(
        programs.len() >= 50,
        "MM.3 corpus sanity check expects the committed IFC corpus"
    );

    let mut compared_programs = 0usize;
    for program in programs {
        let trace = ifc_reference_trace_for_sme_domain(&program.name);
        if trace.is_empty() {
            continue;
        }
        compared_programs += 1;
        for observer in SecurityLevel::all().iter().copied() {
            assert_eq!(
                sme_visible_trace(observer, &trace),
                label_propagation_visible_trace(observer, &trace),
                "IFC corpus program {} ({:?}) diverged for observer {observer}",
                program.name,
                program.category
            );
        }
    }

    assert!(
        compared_programs >= 30,
        "MM.3 requires at least 30 real-program equivalence checks in the SME V1 domain"
    );
}

#[test]
fn top_secret_is_outside_sme_v1_equivalence_domain() {
    assert_eq!(LabelClass::TopSecret.level(), 4);
    assert!(
        SecurityLevel::all()
            .iter()
            .copied()
            .all(|level| security_level_to_label_class(level) != LabelClass::TopSecret)
    );
    assert!(!LabelClass::TopSecret.can_flow_to(&observer_clearance(SecurityLevel::Secret)));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn sme_view_matches_label_propagation_view_for_terminating_traces(
        observer in security_level_strategy(),
        trace in proptest::collection::vec(trace_output_strategy(), 0..40),
    ) {
        prop_assert_eq!(
            sme_visible_trace(observer, &trace),
            label_propagation_visible_trace(observer, &trace)
        );
    }
}
