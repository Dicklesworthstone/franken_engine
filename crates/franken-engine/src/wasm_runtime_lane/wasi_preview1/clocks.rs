//! Caller-supplied clock queries, never an ambient operating-system clock.

use std::num::NonZeroU64;
use std::sync::{Arc, Mutex};

use super::super::{
    BTreeSet, FAULT, HostResult, RuntimeCapability, SUCCESS, WASI_PREVIEW1_MODULE,
    WasiPreview1Error, WasmBoundaryValue, WasmFunctionSignature, WasmHostCaller, WasmHostError,
    WasmHostImports, WasmValueType, errno, require_work, valid_range,
};
use super::WasiSourceError;

/// Preview 1 clock IDs. Timestamps and resolutions are unsigned nanoseconds.
/// Realtime's epoch is Unix time; a monotonic timestamp has no wall-clock meaning.
/// A source may return Unsupported for any clock it cannot safely supply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u32)]
pub enum WasiClockId {
    Realtime = 0,
    Monotonic = 1,
    ProcessCpu = 2,
    ThreadCpu = 3,
}

impl WasiClockId {
    fn decode(id: u32) -> Option<Self> {
        match id {
            0 => Some(Self::Realtime),
            1 => Some(Self::Monotonic),
            2 => Some(Self::ProcessCpu),
            3 => Some(Self::ThreadCpu),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WasiClockRequest {
    Resolution(WasiClockId),
    /// The requested maximum lag is forwarded with all 64 bits preserved.
    Time {
        clock: WasiClockId,
        precision_ns: u64,
    },
}

/// Explicit, bounded source for both Preview 1 clock imports. Resolution must
/// be nonzero; monotonic/CPU timestamps must not regress for this instance.
/// Realtime may jump backwards. The adapter rejects invalid readings rather
/// than fabricating a resolution or silently clamping time.
///
/// The source must honor the clock's units/epoch and requested precision, or
/// return an error. It must not block a cooperative executor. There is no timer,
/// sleeping, polling subscription or OS clock fallback behind this interface.
pub trait WasiClockSource: Send + Sync + 'static {
    fn read(&mut self, request: WasiClockRequest) -> Result<u64, WasiSourceError>;
}

impl<F> WasiClockSource for F
where
    F: FnMut(WasiClockRequest) -> Result<u64, WasiSourceError> + Send + Sync + 'static,
{
    fn read(&mut self, request: WasiClockRequest) -> Result<u64, WasiSourceError> {
        self(request)
    }
}

/// One source-query allowance shared by resolution/time calls, startup and
/// later invocations. Actual source attempts remain spent after failure.
/// Replay does not query the clock or spend this source-access quota; existing
/// capability, transcript identity and live VM work gates still apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasiClockLimits {
    pub max_calls: u64,
    /// In addition to typed host dispatch and the metered eight-byte write.
    pub call_work: NonZeroU64,
}

impl Default for WasiClockLimits {
    fn default() -> Self {
        Self {
            max_calls: 4096,
            call_work: NonZeroU64::MIN,
        }
    }
}

struct ClockState<S> {
    source: S,
    remaining: u64,
    last_time: [Option<u64>; 4],
}

impl WasmHostImports {
    /// Install clock_res_get and clock_time_get together in an owned registry.
    /// Requires Timer and VmDispatch through the existing host gate. A resolved
    /// module must declare Timer, and its current policy must authorize it.
    /// No process clock is selected or enabled merely by installing these ABIs.
    /// Failure consumes the registry, never publishes only one clock binding,
    /// and never replaces a preexisting source. The source stays instance-owned.
    ///
    /// Readings are published in one checked, recorded little-endian write.
    /// Bad pointers/IDs and known work refusal precede source entry. Controls
    /// are checked again after the source; later refusal never becomes errno 0.
    /// Source effects cannot be undone, even if publication or recording fails.
    pub fn with_wasi_clock_source<S: WasiClockSource>(
        mut self,
        source: S,
        limits: WasiClockLimits,
    ) -> Result<Self, WasiPreview1Error> {
        let source = Arc::new(Mutex::new(ClockState {
            source,
            remaining: limits.max_calls,
            last_time: [None; 4],
        }));
        for (name, is_time, params) in [
            ("clock_res_get", false, vec![WasmValueType::I32; 2]),
            (
                "clock_time_get",
                true,
                vec![WasmValueType::I32, WasmValueType::I64, WasmValueType::I32],
            ),
        ] {
            let source = Arc::clone(&source);
            self.define(
                WASI_PREVIEW1_MODULE,
                name,
                WasmFunctionSignature {
                    params,
                    results: vec![WasmValueType::I32],
                },
                BTreeSet::from([RuntimeCapability::Timer]),
                limits.call_work.get(),
                move |caller, args| query(caller, args, is_time, &source),
            )?;
        }
        Ok(self)
    }
}

fn query<S: WasiClockSource>(
    caller: &mut WasmHostCaller<'_, '_>,
    args: &[WasmBoundaryValue],
    is_time: bool,
    source: &Mutex<ClockState<S>>,
) -> HostResult {
    use WasmBoundaryValue::{I32, I64};
    caller.checkpoint()?;
    let (id, precision_ns, address) = match (is_time, args) {
        (false, [I32(id), I32(address)]) => (*id as u32, 0, *address as u32),
        (true, [I32(id), I64(precision), I32(address)]) => {
            (*id as u32, *precision as u64, *address as u32)
        }
        _ => return Err(WasmHostError::trap("invalid WASI clock ABI").into()),
    };
    let Some(clock) = WasiClockId::decode(id) else {
        return errno(28);
    }; // INVAL
    if !valid_range(caller, address, 8) {
        return errno(FAULT);
    }
    require_work(caller, 1)?;
    // Only the two callbacks in this non-cloneable registry own this mutex.
    // Instance execution is exclusive. Poisoning is a VM fault, not a synthetic
    // timestamp or guest errno; the host interruption gate also prevents reentry.
    let mut state = source
        .lock()
        .map_err(|_| WasmHostError::trap("WASI clock source was interrupted"))?;
    if state.remaining == 0 {
        return errno(42);
    } // NOBUFS
    caller.checkpoint()?;
    state.remaining -= 1;
    let request = if is_time {
        WasiClockRequest::Time {
            clock,
            precision_ns,
        }
    } else {
        WasiClockRequest::Resolution(clock)
    };
    let result = state.source.read(request);
    caller.checkpoint()?;
    let value = match result {
        Ok(value) => value,
        Err(error) => return errno(error.errno()),
    };
    let last = state.last_time[clock as usize];
    if (!is_time && value == 0)
        || (is_time && clock != WasiClockId::Realtime && last.is_some_and(|old| value < old))
    {
        return errno(29); // IO: do not publish an invalid source reading
    }
    caller.write_memory(address, &value.to_le_bytes())?;
    if is_time {
        state.last_time[clock as usize] = Some(value);
    }
    errno(SUCCESS)
}
