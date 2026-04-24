#![no_main]

use std::collections::BTreeSet;

use arbitrary::{Arbitrary, Unstructured};
use frankenengine_engine::resource_certificate_consumer::{
    BudgetEnforcementPolicy, BudgetEnforcer, BudgetViolationReason, CertificateDigest,
    CertificateVerdict, EnforcedDimension, EnforcementDecision, EnforcementReceipt,
    EnforcementScope, ExtractedBound,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 4096;
const MAX_BOUNDS: usize = 8;
const MAX_DELTAS: usize = 8;
const MAX_STRING_BYTES: usize = 64;

struct CertificateProgram {
    policy: BudgetEnforcementPolicy,
    current_epoch: SecurityEpoch,
    extension_id: String,
    digest: CertificateDigest,
    scope: EnforcementScope,
    usage_deltas: Vec<(EnforcedDimension, i64)>,
}

impl<'a> Arbitrary<'a> for CertificateProgram {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let current_epoch_raw = u.int_in_range(0_u64..=16)?;
        let current_epoch = SecurityEpoch::from_raw(current_epoch_raw);

        let policy = arbitrary_policy(u)?;
        let extension_id = bounded_string(u, MAX_STRING_BYTES, "ext-fuzz")?;
        let digest = arbitrary_digest(u, current_epoch_raw)?;
        let scope = arbitrary_scope(u)?;

        let delta_count = u.int_in_range(0_usize..=MAX_DELTAS)?;
        let mut usage_deltas = Vec::with_capacity(delta_count);
        for _ in 0..delta_count {
            usage_deltas.push((
                arbitrary_dimension(u)?,
                u.int_in_range(-1_000_000_i64..=25_000_000_i64)?,
            ));
        }

        Ok(Self {
            policy,
            current_epoch,
            extension_id,
            digest,
            scope,
            usage_deltas,
        })
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let _ = serde_json::from_slice::<BudgetEnforcementPolicy>(data);
    let _ = serde_json::from_slice::<EnforcementScope>(data);

    if let Ok(digest) = serde_json::from_slice::<CertificateDigest>(data) {
        exercise_program(CertificateProgram {
            policy: BudgetEnforcementPolicy::default(),
            current_epoch: SecurityEpoch::from_raw(1),
            extension_id: "json-seed-extension".to_string(),
            digest,
            scope: EnforcementScope::General {
                description: "json-seed".to_string(),
            },
            usage_deltas: vec![(EnforcedDimension::Time, 1_000_000)],
        });
    }

    let mut unstructured = Unstructured::new(data);
    let Ok(program) = CertificateProgram::arbitrary(&mut unstructured) else {
        return;
    };
    exercise_program(program);
});

fn exercise_program(program: CertificateProgram) {
    let mut first = BudgetEnforcer::new(program.policy.clone(), program.current_epoch);
    let mut second = first.clone();

    let first_install = first.install_certificate(&program.extension_id, program.digest.clone());
    let second_install = second.install_certificate(&program.extension_id, program.digest.clone());
    assert_eq!(first_install, second_install);
    assert_install_fail_closed(&program, &first_install);

    let first_receipt = first.enforce(
        &program.extension_id,
        program.scope.clone(),
        &program.usage_deltas,
    );
    let second_receipt =
        second.enforce(&program.extension_id, program.scope, &program.usage_deltas);

    assert_eq!(first_receipt.decision, second_receipt.decision);
    assert_eq!(first_receipt.certificate_id, second_receipt.certificate_id);
    assert_eq!(
        first_receipt.budget_snapshot,
        second_receipt.budget_snapshot
    );
    assert_eq!(
        first_receipt.decision_sequence,
        second_receipt.decision_sequence
    );

    if first_install.is_err() && program.policy.fail_closed_on_missing {
        assert!(matches!(
            first_receipt.decision,
            EnforcementDecision::Reject {
                reason: BudgetViolationReason::NoCertificate { .. }
            }
        ));
    }

    let encoded = serde_json::to_string(&first_receipt).expect("receipt should serialize");
    let decoded: EnforcementReceipt =
        serde_json::from_str(&encoded).expect("receipt should deserialize");
    assert_eq!(decoded, first_receipt);
}

fn assert_install_fail_closed(
    program: &CertificateProgram,
    result: &Result<(), BudgetViolationReason>,
) {
    if program.digest.epoch.as_u64() > program.current_epoch.as_u64() {
        assert!(matches!(
            result,
            Err(BudgetViolationReason::EpochMismatch { .. })
        ));
        return;
    }

    if program.digest.verdict == CertificateVerdict::Violated {
        assert!(matches!(
            result,
            Err(BudgetViolationReason::CertificateViolated { .. })
        ));
        return;
    }

    if program.digest.min_confidence_millionths < program.policy.min_confidence_millionths {
        assert!(matches!(
            result,
            Err(BudgetViolationReason::InsufficientConfidence { .. })
        ));
        return;
    }

    if program.policy.max_extensions == 0 {
        assert!(matches!(
            result,
            Err(BudgetViolationReason::ExtensionLimitExceeded { .. })
        ));
        return;
    }

    if program.policy.fail_closed_on_abstention
        && program.digest.verdict == CertificateVerdict::Abstained
    {
        assert!(matches!(
            result,
            Err(BudgetViolationReason::CertificateAbstained { .. })
        ));
    }
}

fn arbitrary_policy(u: &mut Unstructured<'_>) -> arbitrary::Result<BudgetEnforcementPolicy> {
    let throttle_threshold = u.int_in_range(0_u64..=1_500_000)?;
    let reject_threshold = u.int_in_range(throttle_threshold..=1_500_000)?;
    let mut enforced_dimensions = BTreeSet::new();
    let dimension_count = u.int_in_range(0_usize..=DIMENSION_COUNT)?;
    for _ in 0..dimension_count {
        enforced_dimensions.insert(arbitrary_dimension(u)?);
    }

    Ok(BudgetEnforcementPolicy {
        throttle_threshold_millionths: throttle_threshold,
        reject_threshold_millionths: reject_threshold,
        min_confidence_millionths: u.int_in_range(-100_000_i64..=1_500_000_i64)?,
        max_extensions: u.int_in_range(0_usize..=4)?,
        max_receipts: u.int_in_range(0_usize..=8)?,
        enforced_dimensions,
        fail_closed_on_missing: bool::arbitrary(u)?,
        fail_closed_on_abstention: bool::arbitrary(u)?,
        emit_violation_details: bool::arbitrary(u)?,
    })
}

fn arbitrary_digest(
    u: &mut Unstructured<'_>,
    current_epoch_raw: u64,
) -> arbitrary::Result<CertificateDigest> {
    let bound_count = u.int_in_range(0_usize..=MAX_BOUNDS)?;
    let mut bounds = Vec::with_capacity(bound_count);
    for _ in 0..bound_count {
        bounds.push(ExtractedBound {
            dimension: arbitrary_dimension(u)?,
            upper_bound_millionths: u.int_in_range(-1_000_000_i64..=25_000_000_i64)?,
            is_tight: bool::arbitrary(u)?,
            confidence_millionths: u.int_in_range(-100_000_i64..=1_500_000_i64)?,
        });
    }

    let epoch_offset = u.int_in_range(0_u64..=4)?;
    let epoch = if bool::arbitrary(u)? {
        SecurityEpoch::from_raw(current_epoch_raw.saturating_add(epoch_offset))
    } else {
        SecurityEpoch::from_raw(current_epoch_raw.saturating_sub(epoch_offset))
    };

    Ok(CertificateDigest {
        certificate_id: bounded_string(u, MAX_STRING_BYTES, "cert-fuzz")?,
        region_id: bounded_string(u, MAX_STRING_BYTES, "region-fuzz")?,
        epoch,
        verdict: arbitrary_verdict(u)?,
        bounds,
        abstention_count: u.int_in_range(0_usize..=16)?,
        min_confidence_millionths: u.int_in_range(-100_000_i64..=1_500_000_i64)?,
    })
}

fn arbitrary_verdict(u: &mut Unstructured<'_>) -> arbitrary::Result<CertificateVerdict> {
    Ok(match u.int_in_range(0_u8..=3)? {
        0 => CertificateVerdict::Certified,
        1 => CertificateVerdict::Provisional,
        2 => CertificateVerdict::Abstained,
        _ => CertificateVerdict::Violated,
    })
}

fn arbitrary_dimension(u: &mut Unstructured<'_>) -> arbitrary::Result<EnforcedDimension> {
    Ok(match u.int_in_range(0_u8..=6)? {
        0 => EnforcedDimension::Time,
        1 => EnforcedDimension::HeapMemory,
        2 => EnforcedDimension::StackDepth,
        3 => EnforcedDimension::HostcallCount,
        4 => EnforcedDimension::GcPressure,
        5 => EnforcedDimension::ModuleLoadCount,
        _ => EnforcedDimension::IoOperationCount,
    })
}

const DIMENSION_COUNT: usize = 7;

fn arbitrary_scope(u: &mut Unstructured<'_>) -> arbitrary::Result<EnforcementScope> {
    Ok(match u.int_in_range(0_u8..=6)? {
        0 => EnforcementScope::SchedulerAdmission {
            task_type: bounded_string(u, MAX_STRING_BYTES, "dispatch")?,
        },
        1 => EnforcementScope::GcPacing {
            extension_id: bounded_string(u, MAX_STRING_BYTES, "gc-ext")?,
        },
        2 => EnforcementScope::ModuleLoad {
            specifier: bounded_string(u, MAX_STRING_BYTES, "module")?,
        },
        3 => EnforcementScope::SpecializationAdmission {
            receipt_id: bounded_string(u, MAX_STRING_BYTES, "receipt")?,
        },
        4 => EnforcementScope::HostcallInvocation {
            hostcall_id: bounded_string(u, MAX_STRING_BYTES, "hostcall")?,
        },
        5 => EnforcementScope::IoOperation {
            operation_type: bounded_string(u, MAX_STRING_BYTES, "read")?,
        },
        _ => EnforcementScope::General {
            description: bounded_string(u, MAX_STRING_BYTES, "general")?,
        },
    })
}

fn bounded_string(
    u: &mut Unstructured<'_>,
    max_len: usize,
    fallback: &str,
) -> arbitrary::Result<String> {
    let len = u.int_in_range(0_usize..=max_len.min(u.len()))?;
    let bytes = u.bytes(len)?;
    let value = String::from_utf8_lossy(bytes)
        .chars()
        .filter(|ch| !ch.is_control())
        .take(max_len)
        .collect::<String>();
    if value.is_empty() {
        Ok(fallback.to_string())
    } else {
        Ok(value)
    }
}
