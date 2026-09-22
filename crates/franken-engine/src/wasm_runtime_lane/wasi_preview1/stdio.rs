//! Nonblocking, memory-backed standard streams; never OS file descriptors.
//!
//! Iovec metadata is snapshotted before guest writes, all unsigned extents are
//! validated, and work/retention ceilings are checked before stream effects.
//! Live cancellation and transcript refusal can still stop between completed
//! input writes; those writes and the consumed input prefix are retained.
//! Replay uses the existing host transcript, not these providers: it restores
//! guest effects without consuming input again or duplicating captured output.

use super::*;
use std::sync::{Mutex, MutexGuard, TryLockError};

#[path = "stdio/descriptors.rs"]
mod descriptors;
#[path = "stdio/files.rs"]
mod files;
pub use files::WasiReadOnlyFiles;

const AGAIN: i32 = 6;
const BADF: i32 = 8;
const INVAL: i32 = 28;
const IO: i32 = 29;
const NOBUFS: i32 = 42;
const NOMEM: i32 = 48;
const NOSPC: i32 = 51;

/// Per-registry ceilings, independent of VM memory and total instruction caps.
#[derive(Debug, Clone)]
pub struct WasiStdioLimits {
    pub max_stdin_bytes: usize,
    /// Lifetime total across stdout/stderr, NOT replenished by draining output.
    pub max_output_bytes: usize,
    /// Bounds staging, buffer copies and uninterrupted native work per call.
    pub max_transfer_bytes: u32,
    pub max_iovecs: u32,
}

impl Default for WasiStdioLimits {
    fn default() -> Self {
        Self {
            max_stdin_bytes: 1024 * 1024,
            max_output_bytes: 1024 * 1024,
            max_transfer_bytes: 64 * 1024,
            max_iovecs: 1024,
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct WasiCapturedOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WasiStdioAccessError {
    Busy,
    Poisoned,
}

impl fmt::Display for WasiStdioAccessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Busy => "WASI stream observer is busy",
            Self::Poisoned => "WASI stream state is poisoned",
        })
    }
}

impl std::error::Error for WasiStdioAccessError {}

#[derive(Debug)]
struct Streams {
    descriptors: descriptors::Table,
    files: Option<files::FileSystem>,
    input: Vec<u8>,
    consumed: usize,
    output: WasiCapturedOutput,
    emitted: usize,
}

/// Observer for exactly one owned registry. Cloning shares the observer, not
/// the guest VM. Construct a new registry for independent stream positions.
/// No method blocks on another thread, exposes a guest borrow, or refunds a cap.
#[derive(Debug, Clone)]
pub struct WasiStdio {
    streams: Arc<Mutex<Streams>>,
}

impl WasiStdio {
    fn access(&self) -> Result<MutexGuard<'_, Streams>, WasiStdioAccessError> {
        self.streams.try_lock().map_err(|error| match error {
            TryLockError::WouldBlock => WasiStdioAccessError::Busy,
            TryLockError::Poisoned(_) => WasiStdioAccessError::Poisoned,
        })
    }

    /// Transfer captured bytes to the embedder without a second allocation.
    pub fn take_output(&self) -> Result<WasiCapturedOutput, WasiStdioAccessError> {
        Ok(std::mem::take(&mut self.access()?.output))
    }

    pub fn input_consumed(&self) -> Result<usize, WasiStdioAccessError> {
        Ok(self.access()?.consumed)
    }
}

impl WasiPreview1Config {
    /// Add fd_read for explicit stdin (fd 0) and fd_write for captured stdout
    /// and stderr (fds 1 and 2), with descriptor inspection, rights attenuation,
    /// close and renumber. Numbers can change without changing stream identity.
    /// This installs no file/path operations or preopens,
    /// clocks or random sources. proc_exit remains guest-only; it never exits
    /// the host process or touches process stdio.
    ///
    /// fd_read requires FsRead; fd_write requires Console; neither is granted
    /// by configuration. Resolver-backed modules must also declare the required
    /// capabilities. Builtin is needed for imported descriptor-management and
    /// args/proc_exit functions; metadata rights never grant Console or FsRead.
    /// EnvRead is needed only for environment access. All use the host gate.
    pub fn into_imports_with_stdio(
        self,
        granted: BTreeSet<RuntimeCapability>,
        stdin: Vec<u8>,
        limits: WasiStdioLimits,
    ) -> Result<(WasmHostImports, WasiStdio), WasiPreview1Error> {
        self.stdio_imports(granted, stdin, limits, None)
    }

    fn stdio_imports(
        self,
        granted: BTreeSet<RuntimeCapability>,
        stdin: Vec<u8>,
        limits: WasiStdioLimits,
        files: Option<WasiReadOnlyFiles>,
    ) -> Result<(WasmHostImports, WasiStdio), WasiPreview1Error> {
        limit(
            "stdin bytes",
            stdin.len() as u64,
            limits.max_stdin_bytes as u64,
        )?;
        let descriptors = match &files {
            Some(files) => descriptors::Table::with_files(files.max_open_descriptors)?,
            None => descriptors::Table::new(),
        };
        let files = files.map(files::FileSystem::build).transpose()?;
        let has_files = files.is_some();
        let mut imports = self.into_imports(granted)?;
        let observer = WasiStdio {
            streams: Arc::new(Mutex::new(Streams {
                descriptors,
                files,
                input: stdin,
                consumed: 0,
                output: WasiCapturedOutput::default(),
                emitted: 0,
            })),
        };
        for (function, capability, read) in [
            ("fd_read", RuntimeCapability::FsRead, true),
            ("fd_write", RuntimeCapability::Console, false),
        ] {
            let streams = Arc::clone(&observer.streams);
            let limits = limits.clone();
            imports.define(
                WASI_PREVIEW1_MODULE,
                function,
                signature(4),
                BTreeSet::from([capability]),
                1,
                move |caller, arguments| {
                    let arguments = words(arguments)?;
                    let outcome = if read {
                        read_input(caller, arguments, &streams, &limits, None)
                    } else {
                        write_output(caller, arguments, &streams, &limits)
                    };
                    match outcome {
                        Ok(()) => errno(SUCCESS),
                        Err(IoFailure::Errno(code)) => errno(code),
                        Err(IoFailure::Vm(error)) => Err(error),
                    }
                },
            )?;
        }
        descriptors::install(&mut imports, &observer.streams, has_files)?;
        if has_files {
            files::install(&mut imports, &observer.streams, &limits)?;
        }
        Ok((imports, observer))
    }
}

enum IoFailure {
    Errno(i32),
    Vm(WasmNumericVmError),
}
impl From<WasmNumericVmError> for IoFailure {
    fn from(error: WasmNumericVmError) -> Self {
        Self::Vm(error)
    }
}
type IoResult<T> = Result<T, IoFailure>;

fn access(streams: &Mutex<Streams>) -> IoResult<MutexGuard<'_, Streams>> {
    streams.try_lock().map_err(|error| {
        IoFailure::Errno(match error {
            TryLockError::WouldBlock => AGAIN,
            TryLockError::Poisoned(_) => IO,
        })
    })
}

struct IoPlan {
    buffers: Vec<(u32, u32)>,
    length: u32,
}

fn prepare(
    caller: &mut WasmHostCaller<'_, '_>,
    table: u32,
    count: u32,
    result: u32,
    limits: &WasiStdioLimits,
) -> IoResult<IoPlan> {
    caller.checkpoint()?;
    if count > limits.max_iovecs {
        return Err(IoFailure::Errno(INVAL));
    }
    let bytes = count.checked_mul(8).ok_or(IoFailure::Errno(INVAL))?;
    if !valid_range(caller, table, u64::from(bytes)) || !valid_range(caller, result, 4) {
        return Err(IoFailure::Errno(FAULT));
    }
    let size = caller.memory_size_bytes().ok_or(IoFailure::Errno(FAULT))? as u64;
    // Bound count-controlled allocation and descriptor decoding before either.
    caller.charge_work(u64::from(count))?;
    let mut buffers = Vec::new();
    buffers
        .try_reserve_exact(count as usize)
        .map_err(|_| IoFailure::Errno(NOMEM))?;
    let metadata = caller.read_memory(table, bytes)?;
    let mut length = 0_u32;
    for record in metadata.chunks_exact(8) {
        let address = u32::from_le_bytes([record[0], record[1], record[2], record[3]]);
        let width = u32::from_le_bytes([record[4], record[5], record[6], record[7]]);
        if u64::from(address) + u64::from(width) > size {
            return Err(IoFailure::Errno(FAULT));
        }
        length = length
            .checked_add(width)
            .filter(|n| *n <= limits.max_transfer_bytes)
            .ok_or(IoFailure::Errno(NOBUFS))?;
        buffers.push((address, width));
    }
    Ok(IoPlan { buffers, length })
}

fn write_output(
    caller: &mut WasmHostCaller<'_, '_>,
    [fd, table, count, result]: [u32; 4],
    streams: &Mutex<Streams>,
    limits: &WasiStdioLimits,
) -> IoResult<()> {
    let mut streams = access(streams)?;
    streams.descriptors.charge(caller)?;
    let stream = streams.descriptors.writable(fd)?;
    let plan = prepare(caller, table, count, result, limits)?;
    let next = streams
        .emitted
        .checked_add(plan.length as usize)
        .filter(|n| *n <= limits.max_output_bytes)
        .ok_or(IoFailure::Errno(NOSPC))?;
    let native_copy = u64::from(plan.length).div_ceil(64) * 2;
    let buffer_work = plan
        .buffers
        .iter()
        .map(|(_, n)| u64::from(*n).div_ceil(64))
        .sum::<u64>();
    require_work(caller, native_copy + buffer_work + 1)?;
    caller.charge_work(native_copy)?;
    let mut staged = Vec::new();
    staged
        .try_reserve_exact(plan.length as usize)
        .map_err(|_| IoFailure::Errno(NOMEM))?;
    let output = if stream == descriptors::Stream::Output {
        &mut streams.output.stdout
    } else {
        &mut streams.output.stderr
    };
    output
        .try_reserve_exact(plan.length as usize)
        .map_err(|_| IoFailure::Errno(NOMEM))?;
    for (address, width) in plan.buffers {
        staged.extend_from_slice(caller.read_memory(address, width)?);
    }
    // Snapshot all bytes before publishing the count: result may alias a source
    // buffer or its iovec table. Refusal of this count write cannot append
    // output; a later callback-return or transcript-finalization fault retains
    // already-published output, just like other completed host effects.
    caller.write_memory(result, &plan.length.to_le_bytes())?;
    output.extend_from_slice(&staged);
    streams.emitted = next;
    Ok(())
}

fn read_input(
    caller: &mut WasmHostCaller<'_, '_>,
    [fd, table, count, result]: [u32; 4],
    streams: &Mutex<Streams>,
    limits: &WasiStdioLimits,
    offset: Option<u64>,
) -> IoResult<()> {
    let mut streams = access(streams)?;
    streams.descriptors.charge(caller)?;
    let descriptor = streams.descriptors.readable(fd)?;
    let slot = streams.descriptors.index(fd)?;
    let file = match descriptor.stream {
        descriptors::Stream::File(index) => Some(Arc::clone(
            streams
                .files
                .as_ref()
                .ok_or(IoFailure::Errno(BADF))?
                .bytes(index)?,
        )),
        _ => None,
    };
    if offset.is_some() {
        if file.is_none() {
            return Err(IoFailure::Errno(descriptors::SPIPE));
        }
        descriptors::require_right(descriptor, descriptors::READ | descriptors::SEEK)?;
    }
    let mut position = offset.unwrap_or(if file.is_some() {
        descriptor.cursor
    } else {
        streams.consumed as u64
    });
    let size = file
        .as_ref()
        .map_or(streams.input.len(), |bytes| bytes.len()) as u64;
    let plan = prepare(caller, table, count, result, limits)?;
    let actual = u64::from(plan.length).min(size.saturating_sub(position)) as usize;
    let mut remaining = actual;
    let mut work = 1_u64; // final nread write, including EOF
    for (_, width) in &plan.buffers {
        let copied = remaining.min(*width as usize);
        work += (copied as u64).div_ceil(64);
        remaining -= copied;
    }
    require_work(caller, work)?;
    let mut remaining = actual;
    for (address, width) in plan.buffers {
        if remaining == 0 {
            break;
        }
        let copied = remaining.min(width as usize);
        if copied == 0 {
            continue;
        }
        let start = position as usize; // copied > 0 implies position < bounded payload length.
        if let Some(bytes) = &file {
            caller.write_memory(address, &bytes[start..start + copied])?;
        } else {
            caller.write_memory(address, &streams.input[start..start + copied])?;
        }
        // This completed prefix is consumed even when a later cancellation or
        // transcript refusal terminates the callback. No synthetic rollback.
        position += copied as u64;
        if offset.is_none() {
            if file.is_some() {
                streams.descriptors.set_slot_cursor(slot, position);
            } else {
                streams.consumed += copied;
            }
        }
        remaining -= copied;
    }
    caller.write_memory(result, &(actual as u32).to_le_bytes())?;
    Ok(())
}
