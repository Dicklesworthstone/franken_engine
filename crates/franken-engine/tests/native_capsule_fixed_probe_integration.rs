#![cfg(feature = "native-capsule-fixed-probe")]

use franken_native_capsule_worker::WorkerError;
use frankenengine_engine::native_capsule_fixed_probe::{
    NativeCapsuleProbeError, NativeCapsuleProbeRuntime, PreparedNativeCapsuleProbe,
    fixed_probe_plan,
};
use frankenengine_native_capsule::CapsuleError;
use frankenengine_native_capsule_api::{
    ActivationAuthorizationV1, ActivationPhase, AuthorityProfile, CodeMode, CompileAuthorizationV1,
    CompileBudgetsV1, ContractError, ExecutionProfile, FaultDomain, FixedNativeRegionPlanV0,
    Hash32, OperatorMode, SandboxProfile,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn profile() -> ExecutionProfile {
    ExecutionProfile {
        code_mode: CodeMode::Jit,
        fault_domain: FaultDomain::EmbeddedProcess,
        authority_profile: AuthorityProfile::TrustedThroughput,
        sandbox_profile: SandboxProfile::None,
        operator_mode: OperatorMode::Preferred,
    }
}

fn compile_authorization(
    plan: &FixedNativeRegionPlanV0,
) -> Result<CompileAuthorizationV1, ContractError> {
    Ok(CompileAuthorizationV1 {
        authorization_id: Hash32::of(b"engine-integration-fixed-probe-compile-authorization"),
        plan_sha256: plan.canonical_hash()?,
        target: plan.target,
        profile: profile(),
        budgets: CompileBudgetsV1 {
            elapsed_ns: 10_000_000_000,
            transient_bytes: 128 * 1024 * 1024,
            output_bytes: 1024 * 1024,
        },
        policy_epoch: 7,
        security_epoch: 11,
        not_before_unix_ns: 1,
        expires_unix_ns: 3,
        nonce: Hash32::of(b"engine-integration-fixed-probe-compile-nonce"),
    })
}

fn activation_authorization(
    prepared: &PreparedNativeCapsuleProbe,
) -> Result<ActivationAuthorizationV1, ContractError> {
    let receipt = prepared.compilation_receipt();
    Ok(ActivationAuthorizationV1 {
        authorization_id: Hash32::of(b"engine-integration-fixed-probe-activation-authorization"),
        compile_authorization_id: receipt.authorization_id,
        compile_receipt_sha256: receipt.canonical_hash()?,
        rco_sha256: prepared.sealed_rco().payload_sha256,
        target: prepared.sealed_rco().payload.target,
        profile: profile(),
        executable_byte_budget: 1024 * 1024,
        policy_epoch: 7,
        security_epoch: 11,
        not_before_unix_ns: 1,
        expires_unix_ns: 3,
        nonce: Hash32::of(b"engine-integration-fixed-probe-activation-nonce"),
    })
}

fn wrapping_sum_to_exclusive(input: u64) -> u64 {
    (0..input).fold(0_u64, u64::wrapping_add)
}

#[test]
fn engine_plan_compiles_enters_native_code_and_retires() -> TestResult {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return Ok(());
    }

    let plan = fixed_probe_plan(100_000)?;
    let compile_authorization = compile_authorization(&plan)?;
    let prepared = PreparedNativeCapsuleProbe::prepare(100_000, &compile_authorization, 2)?;
    assert_eq!(prepared.plan(), &plan);

    let activation_authorization = activation_authorization(&prepared)?;
    let mut runtime = NativeCapsuleProbeRuntime::default();
    let active = runtime.activate(&prepared, &activation_authorization, 2)?;
    assert_eq!(
        active.activation_receipt().phase,
        ActivationPhase::EntryEnabled
    );
    for input in [0, 1, 2, 10, 1_000, plan.maximum_input] {
        assert_eq!(active.execute(input)?, wrapping_sum_to_exclusive(input));
    }
    assert!(matches!(
        active.execute(plan.maximum_input + 1),
        Err(NativeCapsuleProbeError::Capsule(
            CapsuleError::InputLimitExceeded
        ))
    ));
    assert!(matches!(
        runtime.activate(&prepared, &activation_authorization, 2),
        Err(NativeCapsuleProbeError::Capsule(
            CapsuleError::ActivationNonceReused
        ))
    ));
    let retirement = active.retire(12)?;
    assert_eq!(
        retirement.activation_id,
        activation_authorization.canonical_hash()?
    );
    assert!(retirement.refunded_executable_bytes > 0);
    Ok(())
}

#[test]
fn plan_and_compile_authorization_mismatch_fail_closed() -> TestResult {
    let plan = fixed_probe_plan(100)?;
    let authorization = compile_authorization(&plan)?;
    assert!(matches!(
        PreparedNativeCapsuleProbe::prepare(101, &authorization, 2),
        Err(NativeCapsuleProbeError::Worker(
            WorkerError::AuthorizationDenied
        ))
    ));
    assert!(fixed_probe_plan(0).is_err());
    Ok(())
}
