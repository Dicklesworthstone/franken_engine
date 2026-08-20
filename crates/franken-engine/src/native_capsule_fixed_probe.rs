//! Engine-owned bring-up bridge to the fixed native-code capsule probe.
//!
//! This module is deliberately available only through the opt-in
//! `native-capsule-fixed-probe` feature. It proves the repository dependency
//! direction and the two distinct authorization phases on one bounded,
//! non-JavaScript probe. It is not a JavaScript tier, a signer, a production
//! router, or evidence of native containment or performance parity.

use franken_native_capsule_worker::{FixedRegionCompilation, WorkerError, compile_fixed_region};
use frankenengine_native_capsule::{ActivationNonceRegistry, CapsuleError, FixedProbeCapsule};
use frankenengine_native_capsule_api::{
    ActivationAuthorizationV1, ActivationReceiptV1, CompilationReceiptV1, CompileAuthorizationV1,
    ContractError, FIXED_CRANELIFT_LOWERING_V1, FIXED_NRP_SCHEMA_V0, FixedNativeRegionPlanV0,
    FixedRegionOperation, Hash32, RetirementReceiptV1, SUM_TO_EXCLUSIVE_SEMANTICS_V1,
    SealedFixedProbeRcoV0, TargetId,
};
use thiserror::Error;

/// Constructs the exact machine-free plan owned by FrankenEngine for the
/// provisional sum-to-exclusive fixed probe.
///
/// # Errors
///
/// Returns a contract error when `maximum_input` is zero or exceeds the
/// provisional fixed-probe ceiling.
pub fn fixed_probe_plan(maximum_input: u64) -> Result<FixedNativeRegionPlanV0, ContractError> {
    let plan = FixedNativeRegionPlanV0 {
        schema_version: FIXED_NRP_SCHEMA_V0,
        target: TargetId::LinuxX86_64V3,
        operation: FixedRegionOperation::SumToExclusiveU64,
        maximum_input,
        semantics_sha256: Hash32::of(SUM_TO_EXCLUSIVE_SEMANTICS_V1),
        lowering_sha256: Hash32::of(FIXED_CRANELIFT_LOWERING_V1),
    };
    plan.validate()?;
    Ok(plan)
}

/// Address-free compiler output awaiting a distinct activation authorization.
///
/// Construction checks an externally verified compile-authorization proposal
/// against the exact Engine-owned plan. This type neither maps nor invokes
/// machine code.
pub struct PreparedNativeCapsuleProbe {
    compilation: FixedRegionCompilation,
}

impl PreparedNativeCapsuleProbe {
    /// Compiles the exact provisional plan after validating the supplied
    /// compile authorization.
    ///
    /// Signature verification, hard worker timeouts, and process-scoped
    /// transient-memory enforcement remain the caller/supervisor's
    /// responsibility; the embedded worker performs only its documented
    /// post-operation admission checks.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the plan bound is invalid or the worker
    /// refuses the plan, authorization, target, resource result, or RCO.
    pub fn prepare(
        maximum_input: u64,
        authorization: &CompileAuthorizationV1,
        now_unix_ns: u64,
    ) -> Result<Self, NativeCapsuleProbeError> {
        let plan = fixed_probe_plan(maximum_input)?;
        let compilation = compile_fixed_region(&plan, authorization, now_unix_ns)?;
        Ok(Self { compilation })
    }

    /// Returns the exact machine-free plan compiled by the worker.
    #[must_use]
    pub fn plan(&self) -> &FixedNativeRegionPlanV0 {
        self.compilation.plan()
    }

    /// Returns the worker receipt proposal that a distinct authority must
    /// inspect and bind before activation.
    #[must_use]
    pub fn compilation_receipt(&self) -> &CompilationReceiptV1 {
        self.compilation.receipt()
    }

    /// Returns the sealed address-free RCO that a distinct authority must
    /// inspect and bind before activation.
    #[must_use]
    pub fn sealed_rco(&self) -> &SealedFixedProbeRcoV0 {
        self.compilation.rco()
    }
}

/// Caller-owned activation context for the provisional fixed probe.
///
/// Each instance defines its own nonce-replay domain. Creating another
/// instance therefore does not provide process-wide, durable, or
/// cross-process replay protection. Production routing remains blocked on the
/// ADR's external verifier and durable replay authority.
#[derive(Debug, Default)]
pub struct NativeCapsuleProbeRuntime {
    nonces: ActivationNonceRegistry,
}

impl NativeCapsuleProbeRuntime {
    /// Validates and activates a prepared fixed probe using a separately
    /// issued activation authorization.
    ///
    /// # Errors
    ///
    /// Returns a typed error before native entry when authorization, receipt,
    /// RCO, target features, replay state, or executable-memory admission
    /// fails.
    pub fn activate(
        &mut self,
        prepared: &PreparedNativeCapsuleProbe,
        authorization: &ActivationAuthorizationV1,
        now_unix_ns: u64,
    ) -> Result<ActiveNativeCapsuleProbe, NativeCapsuleProbeError> {
        let capsule = FixedProbeCapsule::activate(
            &prepared.compilation,
            authorization,
            now_unix_ns,
            &mut self.nonces,
        )?;
        Ok(ActiveNativeCapsuleProbe { capsule })
    }
}

/// Live fixed-probe capsule after successful validation, mapping, and entry
/// enablement.
///
/// Dropping this value performs the capsule's best-effort cleanup. Call
/// [`Self::retire`] when a retirement receipt is required.
pub struct ActiveNativeCapsuleProbe {
    capsule: FixedProbeCapsule,
}

impl ActiveNativeCapsuleProbe {
    /// Returns the exact activation receipt proposal for the enabled image.
    #[must_use]
    pub fn activation_receipt(&self) -> &ActivationReceiptV1 {
        self.capsule.activation_receipt()
    }

    /// Executes the exact fixed `u64 -> u64` native probe.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the input exceeds the plan ceiling or the
    /// validated entrypoint is unavailable before entry.
    pub fn execute(&self, input: u64) -> Result<u64, NativeCapsuleProbeError> {
        Ok(self.capsule.execute(input)?)
    }

    /// Removes executable entry, zeroes and unmaps the image, and returns the
    /// linked retirement receipt proposal.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the retirement epoch is invalid or the
    /// executable-memory retirement transition fails.
    pub fn retire(
        self,
        retirement_epoch: u64,
    ) -> Result<RetirementReceiptV1, NativeCapsuleProbeError> {
        Ok(self.capsule.retire(retirement_epoch)?)
    }
}

/// Fail-closed errors from the Engine-owned fixed-probe bridge.
#[derive(Debug, Error)]
pub enum NativeCapsuleProbeError {
    /// Engine-owned plan construction or canonical encoding failed.
    #[error("native capsule plan contract failed: {0}")]
    Contract(#[from] ContractError),
    /// The authority-free compiler worker refused the request or output.
    #[error("native capsule compilation failed: {0}")]
    Worker(#[from] WorkerError),
    /// Activation, native entry, or retirement failed.
    #[error("native capsule runtime failed: {0}")]
    Capsule(#[from] CapsuleError),
}
