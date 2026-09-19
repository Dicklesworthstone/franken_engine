//! Explicit system sources for the Preview 1 ABI. No ambient providers.
//!
//! The embedder supplies the implementation and its work/call/byte limits.
//! Capability and module-manifest checks still happen in the existing linker;
//! installing a source grants nothing. Host recording captures the resulting
//! guest writes, and replay uses those writes without re-entering the source.
//! Protect recordings: random bytes can become secrets in the guest program.
//!
//! ABI: WebAssembly/WASI Preview 1 WITX (`random_get`). Sources are trusted Rust,
//! not sandboxed code. A logical work charge does not bound a blocking source's
//! wall time or allocations. Providers must be nonblocking and bounded, and the
//! surrounding policy must authorize release of their output into guest state.

use std::num::NonZeroU64;

use super::*;

/// A sanitized source failure. Native diagnostics are never copied into guest
/// memory. VM budget, capability, cancellation and recording failures are NOT
/// source errors and must never be converted into a successful errno result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WasiSourceError {
    WouldBlock,
    Unsupported,
    Io,
}

impl WasiSourceError {
    fn errno(self) -> i32 {
        match self {
            Self::WouldBlock => 6,
            Self::Unsupported => 58,
            Self::Io => 29,
        }
    }
}

impl fmt::Display for WasiSourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::WouldBlock => "WASI source would block",
            Self::Unsupported => "WASI source operation is unsupported",
            Self::Io => "WASI source failed",
        })
    }
}

impl std::error::Error for WasiSourceError {}

/// An explicitly authorized cryptographic entropy implementation. Success must
/// fill the ENTIRE slice with fresh, cryptographically secure random bytes.
/// A source must fail rather than substitute predictable bytes on exhaustion.
/// This interface cannot establish the quality of a caller-supplied source;
/// scripted sources are appropriate for tests, not cryptographic production use.
/// No OS RNG, seed, process environment or fallback is installed implicitly.
///
/// A source may have consumed entropy before returning an error. Those external
/// effects are never rolled back or retried by this adapter. The scratch slice
/// cannot outlive the call and is not a direct view of guest memory.
pub trait WasiRandomSource: Send + Sync + 'static {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), WasiSourceError>;
}

impl<F> WasiRandomSource for F
where
    F: FnMut(&mut [u8]) -> Result<(), WasiSourceError> + Send + Sync + 'static,
{
    fn fill(&mut self, output: &mut [u8]) -> Result<(), WasiSourceError> {
        self(output)
    }
}

/// Limits for one owned source/registry, across startup and later invocations.
/// Attempts that actually enter the source consume a call and their requested
/// bytes even on source failure or later VM refusal. No drop, retry, or output
/// inspection refunds this quota. Replay does not consume source quota because
/// it does not access the source; it still pays the VM's current work limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasiRandomLimits {
    /// Maximum temporary allocation and source request size per call.
    pub max_request_bytes: u32,
    pub max_total_bytes: u64,
    pub max_calls: u64,
    /// Fixed provider work, in addition to typed dispatch and three units per
    /// 64-byte group (scratch initialization, source filling, guest copying).
    pub call_work: NonZeroU64,
}

impl Default for WasiRandomLimits {
    fn default() -> Self {
        Self {
            max_request_bytes: 65_536,
            max_total_bytes: 16 * 1024 * 1024,
            max_calls: 4096,
            call_work: NonZeroU64::MIN,
        }
    }
}

impl WasmHostImports {
    /// Install `random_get: (i32, i32) -> i32` in an existing explicit registry.
    /// The registry is consumed on configuration failure; no partially updated
    /// registry is returned. Duplicate bindings never replace the first source.
    /// RandomRead (NOT Builtin) and VmDispatch must be granted by the provider,
    /// declared by a resolved module, and authorized by its current policy.
    ///
    /// Full unsigned pointer validation, request limits and known work checks
    /// precede source entry. Source output is staged; source failure, a bounds
    /// fault or a later VM refusal cannot leave a partial entropy buffer.
    /// A concurrent revocation/shared-work charge or recorder failure can occur
    /// after source entry. Completed source effects and attempt quotas remain
    /// consumed, but output publication fails through the ordinary VM boundary.
    pub fn with_wasi_random_source<S: WasiRandomSource>(
        mut self,
        mut source: S,
        limits: WasiRandomLimits,
    ) -> Result<Self, WasiPreview1Error> {
        let mut remaining_calls = limits.max_calls;
        let mut remaining_bytes = limits.max_total_bytes;
        self.define(
            WASI_PREVIEW1_MODULE,
            "random_get",
            signature(2),
            BTreeSet::from([RuntimeCapability::RandomRead]),
            limits.call_work.get(),
            move |caller, arguments| {
                caller.checkpoint()?;
                let [address, length] = words(arguments)?;
                if !valid_range(caller, address, u64::from(length)) {
                    return errno(FAULT);
                }
                // Empty, in-bounds requests need no entropy or source quota.
                // A module without memory still cannot invent an empty buffer.
                if length == 0 {
                    return errno(SUCCESS);
                }
                if length > limits.max_request_bytes
                    || u64::from(length) > remaining_bytes
                    || remaining_calls == 0
                {
                    return errno(42); // NOBUFS: explicit provider resource limit
                }
                let copy_work = u64::from(length).div_ceil(64);
                require_work(caller, copy_work * 3)?;
                caller.charge_work(copy_work * 2)?;
                let mut output = Vec::new();
                if output.try_reserve_exact(length as usize).is_err() {
                    return errno(48); // NOMEM; no source was entered
                }
                output.resize(length as usize, 0);
                caller.checkpoint()?;
                remaining_calls -= 1;
                remaining_bytes -= u64::from(length);
                let result = source.fill(&mut output);
                // A source cannot turn a concurrent authority revocation into
                // a successful errno by returning either success or an IO error.
                caller.checkpoint()?;
                if let Err(error) = result {
                    return errno(error.errno());
                }
                // Includes the existing pre-mutation transcript reservation.
                caller.write_memory(address, &output)?;
                errno(SUCCESS)
            },
        )?;
        Ok(self)
    }
}
