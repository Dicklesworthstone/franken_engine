//! Bounded recording and effect-free replay of entered native host callbacks.
//!
//! A transcript records typed outcomes, successful guest-memory writes and
//! charged provider work. Replay never invokes the provider. The live linker,
//! ABI and capability gates still run; a transcript is data, never a grant.
//! Full memory fingerprints bind even reads through unexported memory. Both
//! recording and replay charge one work unit per 64 memory bytes for this scan.
//!
//! Snapshots are prefixes of entered host calls, not complete incident reports.
//! Verify replay consumption explicitly. Guest invocations, external effects,
//! policy denials before host entry and provider panics are not recorded here.
//! The digest detects corruption, NOT malicious authorship: authenticate and
//! bind externally supplied transcripts to the intended incident before use.
//! Recorded buffers can contain secrets and need the same protection as memory.

use std::collections::BTreeSet;
use std::fmt;
use std::io::{self, Write};
use std::sync::{Arc, Mutex, MutexGuard};

use serde::{Deserialize, Serialize};

use crate::capability::RuntimeCapability;
use crate::hash_tiers::ContentHash;
use super::{WasmBoundaryValue, WasmFunctionSignature};
use super::numeric::{WasmHostError, WasmNumericLimits, WasmNumericVmError};

type Outcome = Result<Vec<WasmBoundaryValue>, WasmNumericVmError>;
const VERSION: u32 = 1;
// Reserve space for the envelope, array separators and empty-record overhead.
const ENVELOPE_RESERVE: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WasmHostTraceLimits {
    pub max_calls: usize,
    /// Maximum canonical JSON bytes, not an estimate of the allocator's heap.
    pub max_bytes: usize,
}

impl Default for WasmHostTraceLimits {
    fn default() -> Self { Self { max_calls: 4096, max_bytes: 8 * 1024 * 1024 } }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WasmHostTraceError {
    AlreadyConfigured,
    InvalidLimits,
    LimitExceeded,
    Unavailable,
    InvalidTranscript,
    Diverged { call: usize },
    Exhausted { call: usize },
    Incomplete { remaining: usize },
}

impl fmt::Display for WasmHostTraceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyConfigured => f.write_str("host tracing is already configured"),
            Self::InvalidLimits => f.write_str("invalid host transcript limits"),
            Self::LimitExceeded => f.write_str("host transcript limit exceeded"),
            Self::Unavailable => f.write_str("host transcript is busy, poisoned or incomplete"),
            Self::InvalidTranscript => f.write_str("invalid host transcript or digest"),
            Self::Diverged { call } => write!(f, "host replay diverged at call {call}"),
            Self::Exhausted { call } => write!(f, "host replay exhausted before call {call}"),
            Self::Incomplete { remaining } => write!(f, "host replay has {remaining} unconsumed calls"),
        }
    }
}

impl std::error::Error for WasmHostTraceError {}
impl From<WasmHostTraceError> for WasmNumericVmError {
    fn from(error: WasmHostTraceError) -> Self { WasmHostError::Trace(error).into() }
}

fn checked_limits(limits: WasmHostTraceLimits) -> Result<(), WasmHostTraceError> {
    if limits.max_bytes < ENVELOPE_RESERVE { return Err(WasmHostTraceError::InvalidLimits); }
    Ok(())
}

// Stop serialization at the byte ceiling rather than allocating an unbounded
// JSON buffer and checking afterward. Vec growth is fallible too.
struct BoundedJson { bytes: Vec<u8>, max: usize }
impl Write for BoundedJson {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.max.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other("transcript byte limit"));
        }
        self.bytes.try_reserve(bytes.len()).map_err(io::Error::other)?;
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

fn json(value: &impl Serialize, max: usize) -> Result<Vec<u8>, WasmHostTraceError> {
    let mut writer = BoundedJson { bytes: Vec::new(), max };
    serde_json::to_writer(&mut writer, value).map_err(|_| WasmHostTraceError::LimitExceeded)?;
    Ok(writer.bytes)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    module: String,
    name: String,
    function_index: u32,
    arguments: Vec<WasmBoundaryValue>,
    signature: WasmFunctionSignature,
    required: BTreeSet<RuntimeCapability>,
    call_cost: u64,
    limits: WasmNumericLimits,
    entry_work: u64,
    call_depth: u32,
    memory: Option<(u64, ContentHash)>,
}

#[derive(Serialize)]
pub(crate) struct CallContext<'a> {
    pub module: &'a str,
    pub name: &'a str,
    pub function_index: u32,
    pub arguments: &'a [WasmBoundaryValue],
    pub signature: &'a WasmFunctionSignature,
    pub required: &'a BTreeSet<RuntimeCapability>,
    pub call_cost: u64,
    pub limits: &'a WasmNumericLimits,
    pub entry_work: u64,
    pub call_depth: u32,
    pub memory: Option<(u64, ContentHash)>,
}

impl Header {
    fn matches(&self, other: &CallContext<'_>) -> bool {
        self.module == other.module && self.name == other.name
            && self.function_index == other.function_index && self.arguments.as_slice() == other.arguments
            && self.signature == *other.signature && self.required == *other.required
            && self.call_cost == other.call_cost && self.limits == *other.limits
            && self.entry_work == other.entry_work && self.call_depth == other.call_depth
            && self.memory == other.memory
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MemoryWrite {
    pub address: u32,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CallRecord {
    header: Header,
    pub writes: Vec<MemoryWrite>,
    pub work: u64,
    pub outcome: Outcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TranscriptData { version: u32, calls: Vec<CallRecord> }

/// Immutable recorded host effects. Deserialize only through `from_json`, which
/// enforces the caller's byte/call ceilings, schema and content digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WasmHostTranscript { data: TranscriptData, digest: ContentHash }

impl WasmHostTranscript {
    pub fn call_count(&self) -> usize { self.data.calls.len() }
    pub fn digest(&self) -> ContentHash { self.digest }

    pub fn to_json(&self, limits: WasmHostTraceLimits) -> Result<Vec<u8>, WasmHostTraceError> {
        self.validate(limits)?;
        json(self, limits.max_bytes)
    }

    pub fn from_json(bytes: &[u8], limits: WasmHostTraceLimits) -> Result<Self, WasmHostTraceError> {
        checked_limits(limits)?;
        if bytes.len() > limits.max_bytes { return Err(WasmHostTraceError::LimitExceeded); }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire { data: TranscriptData, digest: ContentHash }
        let wire: Wire = serde_json::from_slice(bytes).map_err(|_| WasmHostTraceError::InvalidTranscript)?;
        let transcript = Self { data: wire.data, digest: wire.digest };
        transcript.validate(limits)?;
        Ok(transcript)
    }

    fn validate(&self, limits: WasmHostTraceLimits) -> Result<(), WasmHostTraceError> {
        checked_limits(limits)?;
        if self.data.calls.len() > limits.max_calls { return Err(WasmHostTraceError::LimitExceeded); }
        if self.data.version != VERSION { return Err(WasmHostTraceError::InvalidTranscript); }
        // Bound the complete envelope as well as the digest's payload.
        json(self, limits.max_bytes)?;
        let bytes = json(&self.data, limits.max_bytes)?;
        if ContentHash::compute(&bytes) != self.digest { return Err(WasmHostTraceError::InvalidTranscript); }
        for call in &self.data.calls {
            if call.header.entry_work.checked_add(call.work)
                .is_none_or(|work| work > call.header.limits.max_instructions)
            { return Err(WasmHostTraceError::InvalidTranscript); }
            // Only completed writes are retained. Validate all ranges now,
            // including unsigned overflow, before any replay instance exists.
            let mut write_work = 0_u64;
            for write in &call.writes {
                write_work = write_work.checked_add((write.bytes.len() as u64).div_ceil(64))
                    .ok_or(WasmHostTraceError::InvalidTranscript)?;
                if call.header.memory.is_none_or(|(size, _)|
                    (write.address as u64).checked_add(write.bytes.len() as u64)
                        .is_none_or(|end| end > size))
                { return Err(WasmHostTraceError::InvalidTranscript); }
            }
            if write_work > call.work { return Err(WasmHostTraceError::InvalidTranscript); }
        }
        Ok(())
    }
}

#[derive(Debug)]
struct RecordingState {
    limits: WasmHostTraceLimits,
    calls: Vec<CallRecord>,
    used: usize,
    active: bool,
    failed: bool,
}

fn lock<T>(state: &Mutex<T>) -> Result<MutexGuard<'_, T>, WasmHostTraceError> {
    state.try_lock().map_err(|_| WasmHostTraceError::Unavailable)
}

/// Read-only observer that survives a trapped start function. Inspection never
/// holds a mutex across provider code. A panic or recording failure makes the
/// in-progress transcript unusable, rather than publishing a successful prefix.
#[derive(Debug, Clone)]
pub struct WasmHostRecording(Arc<Mutex<RecordingState>>);

impl WasmHostRecording {
    fn new(limits: WasmHostTraceLimits) -> Result<Self, WasmHostTraceError> {
        checked_limits(limits)?;
        Ok(Self(Arc::new(Mutex::new(RecordingState {
            limits, calls: Vec::new(), used: ENVELOPE_RESERVE, active: false, failed: false,
        }))))
    }

    pub fn snapshot(&self) -> Result<WasmHostTranscript, WasmHostTraceError> {
        let state = lock(&self.0)?;
        if state.failed || state.active { return Err(WasmHostTraceError::Unavailable); }
        let data = TranscriptData { version: VERSION, calls: state.calls.clone() };
        let digest = ContentHash::compute(&json(&data, state.limits.max_bytes)?);
        let transcript = WasmHostTranscript { data, digest };
        transcript.validate(state.limits)?;
        Ok(transcript)
    }
}

#[derive(Debug)]
struct ReplayState { transcript: WasmHostTranscript, next: usize, active: bool, failed: bool }

/// Consumption observer. Call `verify_complete` after the intended sequence;
/// running only a valid prefix is not a successful complete replay.
#[derive(Debug, Clone)]
pub struct WasmHostReplay(Arc<Mutex<ReplayState>>);

impl WasmHostReplay {
    pub fn verify_complete(&self) -> Result<(), WasmHostTraceError> {
        let state = lock(&self.0)?;
        if state.failed || state.active { return Err(WasmHostTraceError::Unavailable); }
        let remaining = state.transcript.call_count() - state.next;
        if remaining != 0 { return Err(WasmHostTraceError::Incomplete { remaining }); }
        Ok(())
    }
}

#[derive(Debug, Default)]
pub(crate) enum TraceMode {
    #[default]
    Off,
    Record(WasmHostRecording),
    Replay(WasmHostReplay),
}

impl TraceMode {
    pub fn enabled(&self) -> bool { !matches!(self, Self::Off) }

    pub fn record(&mut self, limits: WasmHostTraceLimits) -> Result<WasmHostRecording, WasmHostTraceError> {
        if self.enabled() { return Err(WasmHostTraceError::AlreadyConfigured); }
        let recording = WasmHostRecording::new(limits)?;
        *self = Self::Record(recording.clone());
        Ok(recording)
    }

    pub fn replay(&mut self, transcript: WasmHostTranscript, limits: WasmHostTraceLimits) -> Result<WasmHostReplay, WasmHostTraceError> {
        if self.enabled() { return Err(WasmHostTraceError::AlreadyConfigured); }
        transcript.validate(limits)?;
        let replay = WasmHostReplay(Arc::new(Mutex::new(ReplayState { transcript, next: 0, active: false, failed: false })));
        *self = Self::Replay(replay.clone());
        Ok(replay)
    }

    pub fn begin(&mut self, context: CallContext<'_>) -> Result<TraceCall, WasmHostTraceError> {
        match self {
            Self::Off => Ok(TraceCall::Off),
            Self::Record(recording) => {
                let mut state = lock(&recording.0)?;
                if state.active || state.failed { return Err(WasmHostTraceError::Unavailable); }
                let room = state.limits.max_bytes.saturating_sub(state.used);
                let encoded = json(&context, room);
                if state.calls.len() >= state.limits.max_calls || encoded.is_err() || state.calls.try_reserve(1).is_err() {
                    state.failed = true;
                    return Err(WasmHostTraceError::LimitExceeded);
                }
                let encoded = encoded?;
                // Decode the already bounded shape rather than cloning before
                // the byte limit has been checked. No user-controlled parser.
                let header: Header = serde_json::from_slice(&encoded).map_err(|_| WasmHostTraceError::InvalidTranscript)?;
                state.active = true;
                Ok(TraceCall::Record(CallRecording {
                    owner: recording.clone(), header, writes: Vec::new(),
                    room, used: encoded.len(), failed: false, finished: false,
                }))
            }
            Self::Replay(replay) => {
                let mut state = lock(&replay.0)?;
                if state.active || state.failed { return Err(WasmHostTraceError::Unavailable); }
                let index = state.next;
                let Some(call) = state.transcript.data.calls.get(index) else {
                    state.failed = true;
                    return Err(WasmHostTraceError::Exhausted { call: index });
                };
                if !call.header.matches(&context) {
                    state.failed = true;
                    return Err(WasmHostTraceError::Diverged { call: index });
                }
                let call = call.clone();
                state.active = true;
                Ok(TraceCall::Replay(Playback { owner: replay.clone(), call, finished: false }))
            }
        }
    }
}

pub(crate) enum TraceCall { Off, Record(CallRecording), Replay(Playback) }
impl TraceCall {
    pub fn recording(&mut self) -> Option<&mut CallRecording> {
        match self { Self::Record(recording) => Some(recording), _ => None }
    }
    pub fn finish(mut self, work: u64, outcome: &Outcome) -> Result<(), WasmHostTraceError> {
        if let Self::Record(recording) = &mut self { recording.finish(work, outcome)?; }
        Ok(())
    }
}

pub(crate) struct CallRecording {
    owner: WasmHostRecording,
    header: Header,
    writes: Vec<MemoryWrite>,
    room: usize,
    used: usize,
    failed: bool,
    finished: bool,
}

impl CallRecording {
    pub fn write(&mut self, address: u32, bytes: &[u8]) -> Result<(), WasmHostTraceError> {
        let result = self.append_write(address, bytes);
        if result.is_err() { self.failed = true; }
        result
    }

    fn append_write(&mut self, address: u32, bytes: &[u8]) -> Result<(), WasmHostTraceError> {
        if self.failed { return Err(WasmHostTraceError::Unavailable); }
        #[derive(Serialize)]
        struct WriteRef<'a> { address: u32, bytes: &'a [u8] }
        let encoded = json(&WriteRef { address, bytes }, self.room.saturating_sub(self.used))?;
        self.writes.try_reserve(1).map_err(|_| WasmHostTraceError::LimitExceeded)?;
        let mut payload = Vec::new();
        payload.try_reserve_exact(bytes.len()).map_err(|_| WasmHostTraceError::LimitExceeded)?;
        payload.extend_from_slice(bytes);
        self.writes.push(MemoryWrite { address, bytes: payload });
        self.used = self.used.saturating_add(encoded.len()).saturating_add(1);
        Ok(())
    }

    fn finish(&mut self, work: u64, outcome: &Outcome) -> Result<(), WasmHostTraceError> {
        if self.failed { return Err(WasmHostTraceError::LimitExceeded); }
        #[derive(Serialize)]
        struct RecordRef<'a> { header: &'a Header, writes: &'a [MemoryWrite], work: u64, outcome: &'a Outcome }
        let bytes = json(&RecordRef { header: &self.header, writes: &self.writes, work, outcome }, self.room.saturating_sub(1))?;
        let mut state = lock(&self.owner.0)?;
        state.calls.push(CallRecord {
            header: self.header.clone(), writes: std::mem::take(&mut self.writes), work, outcome: outcome.clone(),
        });
        state.used += bytes.len() + 1;
        state.active = false;
        self.finished = true;
        Ok(())
    }
}

impl Drop for CallRecording {
    fn drop(&mut self) {
        if !self.finished && let Ok(mut state) = self.owner.0.lock() {
            state.active = false;
            state.failed = true;
        }
    }
}

pub(crate) struct Playback { owner: WasmHostReplay, pub call: CallRecord, finished: bool }
impl Playback {
    pub fn complete(&mut self) -> Result<(), WasmHostTraceError> {
        let mut state = lock(&self.owner.0)?;
        state.next += 1;
        state.active = false;
        self.finished = true;
        Ok(())
    }
}
impl Drop for Playback {
    fn drop(&mut self) {
        if !self.finished && let Ok(mut state) = self.owner.0.lock() {
            state.active = false;
            state.failed = true;
        }
    }
}
