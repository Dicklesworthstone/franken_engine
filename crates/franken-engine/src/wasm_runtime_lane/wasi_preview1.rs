//! Explicit WASI Preview 1 providers for the native executor.
//!
//! The default registry supplies arguments, environment and guest process exit; an explicit stdio
//! factory adds bounded memory-backed streams under `wasi_snapshot_preview1`.
//! Nothing reads the process arguments/environment,
//! opens host files or installs ambient clocks, entropy or sockets. An explicit
//! read-only file factory exposes only supplied bytes under a private preopen.
//! This is an implemented
//! subset, not a full WASI runtime; undeclared services remain unbound.
//!
//! ABI source: WebAssembly/WASI, wasi-0.1/preview1/witx (args/environ functions).
//! Guest pointer failures return WASI FAULT before any output is written. VM
//! budget, cancellation, revocation and transcript refusals remain VM faults,
//! never successful errno returns. Completed writes on later control/recording
//! failure are retained, following the existing host boundary's effect contract.
//! The surrounding host/IFC policy must authorize release of supplied data.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use super::numeric::{
    WasmHostCaller, WasmHostError, WasmHostImports, WasmNumericVm, WasmNumericVmError,
};
use super::{WasmBoundaryValue, WasmFunctionSignature, WasmValueType};
use crate::capability::RuntimeCapability;

pub const WASI_PREVIEW1_MODULE: &str = "wasi_snapshot_preview1";
const SUCCESS: i32 = 0;
const FAULT: i32 = 21;

type HostResult = Result<Vec<WasmBoundaryValue>, WasmNumericVmError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WasiPreview1Error {
    InvalidString {
        field: &'static str,
        index: usize,
    },
    LimitExceeded {
        resource: &'static str,
        actual: u64,
        max: u64,
    },
    AllocationFailed,
    Binding(WasmHostError),
}

impl fmt::Display for WasiPreview1Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidString { field, index } => {
                write!(f, "invalid WASI {field} at index {index}")
            }
            Self::LimitExceeded {
                resource,
                actual,
                max,
            } => {
                write!(f, "WASI {resource} {actual} exceeds limit {max}")
            }
            Self::AllocationFailed => f.write_str("cannot allocate bounded WASI provider data"),
            Self::Binding(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for WasiPreview1Error {}

impl From<WasmHostError> for WasiPreview1Error {
    fn from(error: WasmHostError) -> Self {
        Self::Binding(error)
    }
}

/// Owned input, not an instruction to inherit anything from the host process.
/// UTF-8 byte sizes include one trailing NUL per entry. Environment keys are
/// sorted for deterministic layout, must be nonempty, and cannot contain '='.
#[derive(Debug, Clone)]
pub struct WasiPreview1Config {
    pub arguments: Vec<String>,
    pub environment: BTreeMap<String, String>,
    /// Combined args/environment entry ceiling, checked before packing.
    pub max_strings: usize,
    /// Combined packed args/environment bytes, including '=' and NUL bytes.
    pub max_bytes: usize,
}

impl Default for WasiPreview1Config {
    fn default() -> Self {
        Self {
            arguments: Vec::new(),
            environment: BTreeMap::new(),
            max_strings: 4096,
            max_bytes: 1024 * 1024,
        }
    }
}

fn limit(resource: &'static str, actual: u64, max: u64) -> Result<(), WasiPreview1Error> {
    if actual > max {
        return Err(WasiPreview1Error::LimitExceeded {
            resource,
            actual,
            max,
        });
    }
    Ok(())
}

impl WasiPreview1Config {
    /// Create a fresh owned registry. Bindings do not grant capabilities:
    /// args access and proc_exit require Builtin; environment access requires EnvRead;
    /// the shared linker also requires VmDispatch. Unused registered services
    /// do not add requirements to modules that do not import them.
    ///
    /// The returned registry can receive other explicit providers, recording,
    /// replay and live-control signals before being consumed by instantiation.
    pub fn into_imports(
        self,
        granted: BTreeSet<RuntimeCapability>,
    ) -> Result<WasmHostImports, WasiPreview1Error> {
        let count = (self.arguments.len() as u64).saturating_add(self.environment.len() as u64);
        limit(
            "input strings",
            count,
            (self.max_strings as u64).min(u64::from(u32::MAX) / 4),
        )?;
        let args_bytes = self.arguments.iter().fold(0_u64, |n, s| {
            n.saturating_add(s.len() as u64).saturating_add(1)
        });
        let env_bytes = self.environment.iter().fold(0_u64, |n, (k, v)| {
            n.saturating_add(k.len() as u64)
                .saturating_add(v.len() as u64)
                .saturating_add(2)
        });
        limit(
            "input bytes",
            args_bytes.saturating_add(env_bytes),
            (self.max_bytes as u64).min(u64::from(u32::MAX)),
        )?;
        for (index, value) in self.arguments.iter().enumerate() {
            if value.contains('\0') {
                return Err(WasiPreview1Error::InvalidString {
                    field: "argument",
                    index,
                });
            }
        }
        for (index, (key, value)) in self.environment.iter().enumerate() {
            if key.is_empty() || key.contains('\0') || key.contains('=') || value.contains('\0') {
                return Err(WasiPreview1Error::InvalidString {
                    field: "environment entry",
                    index,
                });
            }
        }
        let arguments = Arc::new(StringTable::pack(
            self.arguments.len(),
            args_bytes as usize,
            self.arguments.iter().map(|value| (value.as_str(), None)),
        )?);
        let environment = Arc::new(StringTable::pack(
            self.environment.len(),
            env_bytes as usize,
            self.environment
                .iter()
                .map(|(key, value)| (key.as_str(), Some(value.as_str()))),
        )?);
        let mut imports = WasmHostImports::new(granted);
        for (table, sizes_name, get_name, capability) in [
            (
                arguments,
                "args_sizes_get",
                "args_get",
                RuntimeCapability::Builtin,
            ),
            (
                environment,
                "environ_sizes_get",
                "environ_get",
                RuntimeCapability::EnvRead,
            ),
        ] {
            let sizes = Arc::clone(&table);
            imports.define(
                WASI_PREVIEW1_MODULE,
                sizes_name,
                signature(2),
                BTreeSet::from([capability]),
                1,
                move |caller, arguments| sizes.write_sizes(caller, words(arguments)?),
            )?;
            imports.define(
                WASI_PREVIEW1_MODULE,
                get_name,
                signature(2),
                BTreeSet::from([capability]),
                1,
                move |caller, arguments| table.write_strings(caller, words(arguments)?),
            )?;
        }
        imports.define(
            WASI_PREVIEW1_MODULE,
            "proc_exit",
            WasmFunctionSignature {
                params: vec![WasmValueType::I32],
                results: Vec::new(),
            },
            BTreeSet::from([RuntimeCapability::Builtin]),
            1,
            |caller, arguments| {
                let [code] = words(arguments)?;
                Err(caller.exit(code))
            },
        )?;
        Ok(imports)
    }
}

/// Execute one command in a fresh, private instance and return its full u32
/// exit status. A normal return from `_start` means zero; only the typed
/// ProcessExit outcome is translated to another status. Traps, denial, budget
/// exhaustion and recording failures remain errors, including after exit.
///
/// Validate `_start: [] -> []` BEFORE linking, allocating or executing binary
/// startup. Exit from binary startup ends the command without invoking `_start`.
/// The instance is consumed on every path, so this API cannot rerun its entry.
/// Keep the separate stdio/recording observers to inspect completed effects.
/// This synchronous embedding API neither exits the host nor installs services;
/// resolver-backed callers retain their existing policy-checked execution API.
pub fn run_command(
    vm: &WasmNumericVm,
    imports: WasmHostImports,
) -> Result<u32, WasmNumericVmError> {
    run_command_with_outcome(vm, imports).map(|outcome| outcome.exit_code())
}

#[derive(Debug)]
struct StringTable {
    offsets: Vec<u32>,
    bytes: Vec<u8>,
}

impl StringTable {
    fn pack<'a>(
        count: usize,
        length: usize,
        entries: impl Iterator<Item = (&'a str, Option<&'a str>)>,
    ) -> Result<Self, WasiPreview1Error> {
        let mut offsets = Vec::new();
        let mut bytes = Vec::new();
        offsets
            .try_reserve_exact(count)
            .map_err(|_| WasiPreview1Error::AllocationFailed)?;
        bytes
            .try_reserve_exact(length)
            .map_err(|_| WasiPreview1Error::AllocationFailed)?;
        for (first, second) in entries {
            offsets.push(bytes.len() as u32);
            bytes.extend_from_slice(first.as_bytes());
            if let Some(value) = second {
                bytes.push(b'=');
                bytes.extend_from_slice(value.as_bytes());
            }
            bytes.push(0);
        }
        Ok(Self { offsets, bytes })
    }

    fn write_sizes(
        &self,
        caller: &mut WasmHostCaller<'_, '_>,
        [count, bytes]: [u32; 2],
    ) -> HostResult {
        if !valid_range(caller, count, 4) || !valid_range(caller, bytes, 4) {
            return errno(FAULT);
        }
        require_work(caller, 2)?;
        caller.write_memory(count, &(self.offsets.len() as u32).to_le_bytes())?;
        caller.write_memory(bytes, &(self.bytes.len() as u32).to_le_bytes())?;
        errno(SUCCESS)
    }

    fn write_strings(
        &self,
        caller: &mut WasmHostCaller<'_, '_>,
        [pointers, buffer]: [u32; 2],
    ) -> HostResult {
        if !valid_range(caller, pointers, self.offsets.len() as u64 * 4)
            || !valid_range(caller, buffer, self.bytes.len() as u64)
        {
            return errno(FAULT);
        }
        // Pointer construction and the payload copy, plus every metered write,
        // must fit before the first write. Cancellation/transcript refusal is
        // still allowed between effects and is never converted to an errno.
        let compute = self.offsets.len() as u64;
        require_work(caller, compute * 2 + (self.bytes.len() as u64).div_ceil(64))?;
        caller.charge_work(compute)?;
        caller.write_memory(buffer, &self.bytes)?;
        for (index, offset) in self.offsets.iter().enumerate() {
            // Validated extents and nonempty NUL-terminated entries imply both
            // addresses fit memory32, even when its one-past-end is 2^32.
            let pointer = buffer
                .checked_add(*offset)
                .ok_or_else(|| WasmHostError::trap("WASI pointer overflow"))?;
            let slot = pointers
                .checked_add(index as u32 * 4)
                .ok_or_else(|| WasmHostError::trap("WASI pointer-table overflow"))?;
            caller.write_memory(slot, &pointer.to_le_bytes())?;
        }
        errno(SUCCESS)
    }
}

fn signature(count: usize) -> WasmFunctionSignature {
    WasmFunctionSignature {
        params: vec![WasmValueType::I32; count],
        results: vec![WasmValueType::I32],
    }
}

fn words<const N: usize>(arguments: &[WasmBoundaryValue]) -> Result<[u32; N], WasmNumericVmError> {
    if arguments.len() != N {
        return Err(WasmHostError::trap("invalid WASI callback arity").into());
    }
    let mut result = [0; N];
    for (target, value) in result.iter_mut().zip(arguments) {
        let WasmBoundaryValue::I32(value) = value else {
            return Err(WasmHostError::trap("invalid WASI callback argument type").into());
        };
        *target = *value as u32;
    }
    Ok(result)
}

fn errno(code: i32) -> HostResult {
    Ok(vec![WasmBoundaryValue::I32(code)])
}

/// Probe without invoking the latched host-buffer fault path: bad WASI
/// pointers are errno values, but exhausted VM authority/work is not.
fn valid_range(caller: &WasmHostCaller<'_, '_>, address: u32, length: u64) -> bool {
    caller.memory_size_bytes().is_some_and(|size| {
        u64::from(address)
            .checked_add(length)
            .is_some_and(|end| end <= size as u64)
    })
}

/// Do not double-charge future buffer operations, but fail/latch now when
/// their known total cannot fit. The caller exclusively borrows this meter.
fn require_work(caller: &mut WasmHostCaller<'_, '_>, work: u64) -> Result<(), WasmNumericVmError> {
    caller.checkpoint()?;
    if work > caller.remaining_work() {
        caller.charge_work(work)?;
    }
    Ok(())
}

#[path = "wasi_preview1/stdio.rs"]
mod stdio;
pub use stdio::{
    WasiCapturedOutput, WasiReadOnlyFiles, WasiStdio, WasiStdioAccessError, WasiStdioLimits,
};

#[path = "wasi_preview1/command.rs"]
mod command;
pub use command::{WasiCommandOutcome, WasiCommandPhase, run_command_with_outcome};

/// Explicit capability-gated system sources; no ambient entropy or clocks.
#[path = "wasi_preview1/sources.rs"]
pub mod sources;
