//! Baseline interpreter skeleton for the current execution-profile contract.
//!
//! Consumes `Ir3Module` and produces execution results carrying the witness
//! events and hostcall decisions that `ExecutionOrchestrator::execute` seals
//! into the `Ir4Module` witness (bd-drb55).  The baseline interpreter is the
//! canonical execution path — all optimized paths must prove equivalence
//! against it (per 9F.1).
//!
//! Two execution profiles are exposed today:
//! - **baseline_deterministic_profile**: conservative budgets for
//!   security-sensitive and resource-constrained contexts.
//! - **baseline_throughput_profile**: larger budgets for performance-oriented
//!   workloads.
//!
//! Membership operators now use deterministic prototype links for the
//! baseline heap so `in` / `instanceof` stop failing closed on the shipped
//! execution path. `object_model.rs` remains the richer semantic source of
//! truth for advanced descriptor/proxy behavior.
//!
//! Both profiles share the same `InterpreterCore` execution logic; the profile
//! difference is in policy (instruction budget, register limit, dispatch
//! strategy), not in a second engine backend.
//!
//! `BTreeMap`/`BTreeSet` provide deterministic internal ordering; observable
//! data properties use explicit ECMAScript own-key order. Hot-path JIT counters
//! use private non-observable storage where iteration order is never exposed.
//! `#![forbid(unsafe_code)]` — no unsafe anywhere.
//!
//! Plan reference: Section 10.2 item 8, bd-2f8.
//! Dependencies: bd-crp (parser), bd-1wa (IR contract), bd-20b (slot registry).

#![allow(
    clippy::collapsible_if,
    clippy::collapsible_match,
    clippy::if_same_then_else,
    clippy::manual_range_contains,
    clippy::map_entry,
    clippy::unnecessary_map_or
)]

use std::borrow::Cow;
use std::cell::{Cell, Ref, RefCell, RefMut};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, LinkedList, VecDeque};
use std::fmt;
use std::fs;
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::rc::{Rc, Weak};
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use aes::cipher::{
    BlockDecryptMut, BlockEncrypt, BlockEncryptMut, KeyIvInit, StreamCipher,
    block_padding::{NoPadding, Pkcs7},
};
use aes_gcm::aead::{AeadInPlace, KeyInit as AeadKeyInit};
use ed25519_dalek::{
    Signature as Ed25519Signature, Signer as Ed25519Signer, Verifier as Ed25519Verifier,
    VerifyingKey,
};
use flate2::{Compression, GzBuilder, read::MultiGzDecoder};
use ghash::universal_hash::UniversalHash as _;
use ghash::{GHash, universal_hash};
use hmac::{Hmac, Mac};
use md5::Md5;
use regex::RegexBuilder;
use regexp_backtrack::{
    BacktrackRegExp, CaptureRetention, Captures, CompiledRegExp, GlobalMatchError, MAX_PATTERN_LEN,
    PATTERN_TOO_LARGE, RetentionBudget,
};
use regexp_input::{RegExpInput, RegExpOutput};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use subtle::ConstantTimeEq;
use url::{Url, form_urlencoded};
use zeroize::Zeroizing;

mod arguments;
mod array_from;
mod array_generic;
mod array_reduce;
mod async_generator;
mod atomics;
mod bigint_ops;
mod blob;
mod builtin_function_lengths;
mod collation;
mod collector;
mod date_locale;
mod event_target;
mod inspect;
mod intl;
mod intl_segmenter;
mod iterator_helpers;
mod json_module;
mod json_parse;
mod json_stringify;
mod legacy_regexp;
mod number_locale;
mod object_integrity;
mod package_resolution;
pub(crate) use package_resolution::is_node_core_module_specifier;
pub mod packed_taint;
mod primitive_conversion;
#[cfg(test)]
mod process_lifecycle_tests;
mod promise_capability;
mod prototype_getters;
mod reflect_invocation;
mod regexp_backtrack;
mod regexp_input;
mod regexp_protocol;
mod regexp_syntax;
mod resizable_buffers;
mod set_algebra;
mod structured_clone;
mod text_codec;
#[cfg(test)]
use async_generator::AsyncGeneratorPhase;
use async_generator::{AsyncGeneratorObject, AsyncGeneratorRuntime};
use collector::GcPin;
pub use collector::GcStats;
use legacy_regexp::{LegacyRegExpMatch, is_legacy_regexp_static};
use object_integrity::ObjectIntegrityOperation;
use primitive_conversion::PrimitiveConversion;
use reflect_invocation::ReflectPropertyOperation;

use frankenengine_core::object_model::{
    BaselineSymbolProperty, OrderedStringMap, SymbolId as CoreSymbolId, canonical_array_index,
};
use frankenengine_extension_host::host_effect_journal::InMemoryHostEffectJournal;
use frankenengine_extension_host::host_io::{
    FsDirEntry, FsMetaResult, FsMetadata, FsOperation, HostIoError, HostIoExceptionProvenance,
    HostIoOutcome, HostIoProvider, HostIoRecorder, SANDBOXED_HOST_IO_MAX_RANDOM_BYTES_PER_REQUEST,
    validate_environment_name,
};
use frankenengine_extension_host::process_spawn::{
    ProcessExit, ProcessLaunch, ProcessSignal, ProcessSpawnError, ProcessSpawnProvider,
    ProcessSpawnRequest, ProcessSpawnResponse, ProcessStdio, ProcessStdioMode,
};

use crate::algebraic_effects::{EffectError, HandlerFailurePayload};
use crate::ast::ParseGoal;
use crate::capability::{
    APPLY_HOSTCALL_TARGET_PREFIX, CapabilityProfile, HostcallDispatchBinding,
    HostcallResultContract, RuntimeCapability, hostcall_registry_row, hostcall_result_contract,
    is_language_operation_tag,
};
use crate::checkpoint::{
    CancellationToken, CheckpointAction, CheckpointGuard, DensityConfig, LoopSite,
};
use crate::deterministic_replay::{NondeterminismSource, NondeterminismTrace};
use crate::engine_object_id::{EngineObjectId, ObjectDomain, SchemaId, derive_id};
use crate::hash_tiers::ContentHash;
use crate::hostcall_effects_migration::{
    InterpreterTimerOutcome, InterpreterTimerRequest, PROCESS_SPAWN_EXECUTABLE_NOT_FOUND_CODE,
    TimerEffectAuthority, TimerEffectPermit, TimerOperation, create_env_read_effect,
    create_fs_effect, create_handler_stack_from_profile_with_effect_providers,
    create_handler_stack_from_profile_with_host_io, create_interpreter_timer_effect,
    create_interpreter_timer_handler_stack, create_network_effect, create_network_host_io_request,
    create_process_spawn_effect, create_random_read_effect,
};
use crate::hostcall_telemetry::{
    FlowLabel, HostcallResult as TelemetryHostcallResult, HostcallType as TelemetryHostcallType,
    RecordInput, RecorderConfig, ResourceDelta, TelemetryRecorder,
};
use crate::ifc_artifacts::Label;
use crate::import_attributes::ImportAttributes;
use crate::intrinsics_codegen::{GeneratedGlue, generate_glue};
use crate::intrinsics_table::{IfcPropagation, ImplBinding, ThisCoercion};
use crate::ir_contract::{
    AccessorKind, CapabilityTag, GLOBAL_FUNCTION_BINDING_KIND, GLOBAL_VAR_BINDING_KIND,
    HostcallDecisionRecord, Ir0Module, Ir3Instruction, Ir3Module, IrHeader, IteratorCloseReason,
    RegRange, WitnessEvent, WitnessEventKind,
};
use crate::iterator_protocol::{
    CloseReason, IterationCompletion, IterationEvent, IterationKind, IterationOperation,
    IterationTrace, IteratorResult, IteratorSymbolKind, IteratorValue, make_close_event,
    make_enumerate_event, make_get_iterator_event, make_next_event,
};
use crate::js_string::JsString;
use crate::lowering_pipeline::{AmbientAuthorityGrant, LoweringContext, lower_ir0_to_ir3};
use crate::module_compatibility_matrix::CompatibilityMode;
#[cfg(test)]
use crate::module_resolver::ResolutionOutcome;
use crate::module_resolver::{
    ExecutionModuleResolver, ImportStyle, MetadataResolutionOutcome, ModuleMetadataTarget,
    ModuleRequest, ModuleSourceKind, ModuleSyntax, NativeBuiltinModule, ResolutionContext,
    ResolutionErrorCode, ResolvedModule, SharedResolutionOutcome, SharedResolvedModule,
    node_builtin_specifier, validate_import_attributes,
};
use crate::object_model::{SymbolId, WellKnownSymbol};
use crate::parser::{
    CanonicalEs2020Parser, ParseError, ParseErrorCode, ParserOptions, ParserSource,
};
use crate::runtime_config::ExecutionConfig;
use crate::runtime_observability::{
    CapabilityDenialReason, RuntimeSecurityMetrics, RuntimeSecurityObservability,
    SecurityEventContext,
};
use crate::stdlib::normalize_unicode_string;

// ---------------------------------------------------------------------------
// WeakMap Storage - Weak Reference Implementation
// ---------------------------------------------------------------------------

/// A WeakMap key: an object (by id) or a symbol outside the global
/// registry (by symbol id).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum WeakMapKey {
    Object(u32),
    Symbol(u32),
}

/// Weak reference storage for WeakMap entries.
/// Keys are stored as weak references and automatically cleaned up on GC.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WeakMapStorage {
    /// Map from object ID to stored value. The object ID itself acts as a weak reference.
    entries: BTreeMap<u32, Value>,
    /// Track which objects are referenced as keys for GC integration
    weak_key_objects: BTreeSet<u32>,
    /// Entries keyed by a symbol that is not in the global registry (ES2023
    /// CanBeHeldWeakly, bd-performance-conformance-bridge-tu32j.16.6). The
    /// engine never reclaims a symbol, so these entries are held strongly.
    #[serde(default)]
    symbol_entries: BTreeMap<u32, Value>,
}

impl WeakMapStorage {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            weak_key_objects: BTreeSet::new(),
            symbol_entries: BTreeMap::new(),
        }
    }

    /// The value stored under a symbol key.
    pub fn get_symbol(&self, symbol: u32) -> Option<&Value> {
        self.symbol_entries.get(&symbol)
    }

    /// Store `value` under a symbol key.
    pub fn set_symbol(&mut self, symbol: u32, value: Value) {
        self.symbol_entries.insert(symbol, value);
    }

    /// Remove a symbol key's entry; whether there was one.
    pub fn delete_symbol(&mut self, symbol: u32) -> bool {
        self.symbol_entries.remove(&symbol).is_some()
    }

    pub fn set(&mut self, key_object_id: u32, value: Value) {
        self.entries.insert(key_object_id, value);
        self.weak_key_objects.insert(key_object_id);
    }

    pub fn get(&self, key_object_id: u32) -> Option<&Value> {
        self.entries.get(&key_object_id)
    }

    pub fn has(&self, key_object_id: u32) -> bool {
        self.entries.contains_key(&key_object_id)
    }

    pub fn delete(&mut self, key_object_id: u32) -> bool {
        let existed = self.entries.remove(&key_object_id).is_some();
        self.weak_key_objects.remove(&key_object_id);
        existed
    }

    /// Remove entries for objects that have been garbage collected.
    /// This is called by the GC system when objects become unreachable.
    pub fn cleanup_collected_objects(&mut self, collected_object_ids: &BTreeSet<u32>) {
        for &object_id in collected_object_ids {
            if self.weak_key_objects.contains(&object_id) {
                self.entries.remove(&object_id);
                self.weak_key_objects.remove(&object_id);
            }
        }
    }

    /// Get all object IDs that this WeakMap is holding as keys.
    /// Used by GC system to determine weak references.
    pub fn get_weak_key_objects(&self) -> &BTreeSet<u32> {
        &self.weak_key_objects
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const COMPONENT: &str = "baseline_interpreter";

/// Default instruction budget for the deterministic profile.
const DEFAULT_QUICKJS_BUDGET: u64 = 100_000;

/// Default instruction budget for the throughput profile.
const DEFAULT_V8_BUDGET: u64 = 1_000_000;

/// Upper bound on retained `Function`-constructor audit/event pairs
/// (bd-8enww.3.4 / bd-fw7zd.8.2). The shared instruction and total-memory
/// budgets already constrain generated-code activity; this count cap is a
/// secondary guard against pathological ceilings.
const MAX_GENERATED_CODE_AUDIT_ENTRIES: usize = 65_536;

/// Fixed parser/lowering workspace reserved before a generated `Function`
/// source is materialized. This covers the empty AST/IR scaffolding and the
/// lowering pipeline's fixed bookkeeping.
const GENERATED_FUNCTION_COMPILATION_FIXED_SCRATCH_BYTES: u64 = 64 * 1024;
/// Conservative combined source/AST/IR0/IR3 workspace per possible generated
/// source byte. Parser and lowering nodes are token-backed (there cannot be
/// more nodes than source units), and one KiB per unit covers their simultaneous
/// records plus text copies. The reservation is charged before argument
/// stringification and transitions atomically into retained-artifact ownership
/// after lowering.
const GENERATED_FUNCTION_COMPILATION_SCRATCH_BYTES_PER_SOURCE_BYTE: u64 = 1024;

/// Default register file size for the deterministic profile.
const DEFAULT_QUICKJS_MAX_REGISTERS: u32 = 256;

/// Default register file size for the throughput profile.
const DEFAULT_V8_MAX_REGISTERS: u32 = 4096;
/// Longest file, in `max_registers` windows, the core keeps as a spare
/// register file (`spare_register_files`); a longer one is freed.
const SPARE_REGISTER_FILE_WINDOWS: usize = 4;
/// Spare register files the core keeps. A generator stepped from inside a
/// function alternates between the caller's file and the activation's,
/// which differ in length: with one spare every install cut or regrew it.
const SPARE_REGISTER_FILES: usize = 2;
/// Default heap object budget for the deterministic profile.
const DEFAULT_QUICKJS_MAX_HEAP_OBJECTS: u32 = 100_000;
/// Default heap object budget for the throughput profile.
const DEFAULT_V8_MAX_HEAP_OBJECTS: u32 = 1_000_000;
/// Default total memory budget for the deterministic profile.
const DEFAULT_QUICKJS_MAX_TOTAL_MEMORY_BYTES: u64 = 64 * 1024 * 1024;
/// Default total memory budget for the throughput profile.
const DEFAULT_V8_MAX_TOTAL_MEMORY_BYTES: u64 = 512 * 1024 * 1024;
/// Console entries a run may retain before it fails closed (conservative profile).
const DEFAULT_QUICKJS_MAX_CONSOLE_ENTRIES: usize = 100_000;
/// Console entries a run may retain before it fails closed (throughput profile).
const DEFAULT_V8_MAX_CONSOLE_ENTRIES: usize = 1_000_000;
/// Bytes of console text a run may retain before it fails closed. Retained
/// console text is not charged to the memory budget, so this is what bounds
/// it; 8 MiB also leaves an embedder's result frame room for the rest of the
/// result.
const DEFAULT_MAX_CONSOLE_BYTES: usize = 8 * 1024 * 1024;
/// Default scope-chain depth budget for all interpreter profiles.
const DEFAULT_MAX_SCOPE_DEPTH: u32 = 512;
/// Epoch of the deterministic wall clock (2026-01-01T00:00:00Z). `Date.now()`
/// and `new Date()` report this epoch plus the virtual time elapsed in the run.
const DETERMINISTIC_EPOCH_MS: i64 = 1_767_225_600_000;
/// Guest instructions per virtual millisecond. Synchronous work advances the
/// virtual wall clock deterministically (so `Date.now()` deltas measure work
/// and busy-waits terminate); firing a timer advances it to the timer's due
/// time (bd-9vouw.59).
const INSTRUCTIONS_PER_VIRTUAL_MS: u64 = 1_000;

/// Domain-separation tag for the HMAC preimage of a [`DecisionReceipt`]
/// (bd-gn3mt). Mirrors the
/// [`crate::tee_attestation_policy`] `QUOTE_SIGNATURE_DOMAIN` pattern so a
/// signature minted for an attestation quote can never collide with one minted
/// for a decision receipt under the same HMAC key.
const RECEIPT_SIGNATURE_DOMAIN: &[u8] = b"FrankenEngine.DecisionReceipt.Signature.v1";

/// Maximum call-stack depth (bd-9vouw.72). A JS-to-JS call pushes a
/// `CallFrame` and continues in the same dispatch loop, so this bounds
/// heap-side frames, not the native stack. Node v22 takes 9,642 frames of a
/// one-argument recursive function before its RangeError.
const MAX_CALL_DEPTH: usize = 10_000;
/// Nested run loops (builtin callbacks, accessors, cross-module re-entry)
/// recurse on the native stack. They are capped separately from JS frames, at
/// the old default call depth, and the provisioned execution stack is sized
/// for that many (`interpreter_execution_stack_bytes`).
const MAX_NATIVE_RUN_LOOP_DEPTH: usize = 256;
/// Register-file extent, part 1: full-width (`max_registers`) windows, what
/// the fixed-stride layout reached at its old default depth (256 frames plus
/// the top-level window).
const REGISTER_FILE_FULL_WIDTH_WINDOWS: usize = MAX_NATIVE_RUN_LOOP_DEPTH + 1;
/// Register-file extent, part 2: registers per configured frame. A callee's
/// window starts right above its caller's verified window, so narrow frames
/// recurse to `max_call_depth` (a one-argument recursive function has a
/// window of about 10 registers); wide ones stop earlier, as they do in Node,
/// whose limit is stack bytes.
const REGISTER_FILE_SLOTS_PER_FRAME: usize = 16;

/// Register slots the file may hold (bd-9vouw.72): the larger of the two
/// extents above. The shallow value/label carriers are not charged to the
/// memory budget, so this is what bounds them: 160,016 slots (about 9 MB) at
/// the default depth with 256-register windows, 257 windows (about 59 MB)
/// with 4096-register windows, as before.
pub(crate) fn register_file_slot_limit(max_call_depth: usize, max_registers: usize) -> usize {
    REGISTER_FILE_FULL_WIDTH_WINDOWS
        .saturating_mul(max_registers)
        .max(
            max_call_depth
                .saturating_add(1)
                .saturating_mul(REGISTER_FILE_SLOTS_PER_FRAME),
        )
}

/// Longest argument list a spread call, `apply`, `Reflect.apply` or
/// `Reflect.construct` accepts (bd-9vouw.50). Arguments past the register
/// frame are staged out of band ([`ArgumentOverflow`]); the list is still
/// charged to the memory budget before it is materialized. Node's own limit
/// comes from its stack, at roughly 10^5.
const MAX_CALL_ARGUMENTS: u32 = 1 << 17;
/// Native stack reserved before baseline execution begins. The interpreter's
/// debug dispatch frame is intentionally large; cross-module wrappers re-enter
/// it recursively while preserving the logical depth in
/// `module_reentrant_call_depth`.
const INTERPRETER_EXECUTION_STACK_BASE_BYTES: usize = 4 * 1024 * 1024;
/// Conservative native-stack allowance for each nested run loop the
/// configuration admits (the smaller of `max_call_depth` and
/// `MAX_NATIVE_RUN_LOOP_DEPTH`). Stack pages remain demand-paged, so the
/// reservation bounds address space without eagerly committing it.
const INTERPRETER_EXECUTION_STACK_PER_CALL_DEPTH_BYTES: usize = 512 * 1024;
/// Deterministic bound for baseline prototype-chain walks.
const MAX_PROTOTYPE_CHAIN_DEPTH: u32 = 64;
const PROXY_TYPE_TAG: &str = "Proxy";
/// The brand of a `stream.Readable` (bd-9vouw.150).
const READABLE_BRAND: &str = "Readable";
/// The brand of a JSON.rawJSON result, its [[IsRawJSON]] slot (bd-9vouw.380).
const RAW_JSON_BRAND: &str = "RawJSON";
/// The failure reason a module record keeps for invalid source, so a later
/// import throws the same SyntaxError (bd-9vouw.389).
const MODULE_SYNTAX_ERROR_REASON_PREFIX: &str = "SyntaxError: ";
const PROXY_TARGET_SLOT: &str = "__proxy_target";
const PROXY_HANDLER_SLOT: &str = "__proxy_handler";
const PROXY_REVOKED_SLOT: &str = "__proxy_revoked";
/// The callable target of a proxy over a function (bd-9vouw.132). Its
/// `PROXY_TARGET_SLOT` then holds the target's own-property storage, which
/// the traps' fallbacks for [[Set]], [[Delete]], ... act on.
const PROXY_CALL_TARGET_SLOT: &str = "__proxy_call_target";
/// A Map's or Set's entry count (bd-9vouw.140): an internal slot, not an own
/// `size` property, so %Map.prototype%.size / %Set.prototype%.size (and a
/// subclass's `get size()`) answer `size` reads.
const COLLECTION_SIZE_SLOT: &str = "__size";
/// The TypeError Object.defineProperty raises for a definition the target
/// rejects; Reflect.defineProperty answers false for exactly this one.
const DEFINE_PROPERTY_REJECTED: &str = "definable property for Object.defineProperty";
/// Built-in class parents the lowering records by name (`class X extends Map`,
/// see `builtin_constructor_name` in the lowering); construction handles
/// each through `initialize_builtin_subclass_instance`.
const LOWERED_BUILTIN_CLASS_PARENTS: [&str; 12] = [
    "Object",
    "Array",
    "Map",
    "Set",
    "Error",
    "TypeError",
    "RangeError",
    "ReferenceError",
    "SyntaxError",
    "EvalError",
    "URIError",
    "AggregateError",
];

const WELL_KNOWN_SYMBOL_SCHEMA: &str = "es2020-symbol-ids-1-13-v1";
const FIRST_DYNAMIC_SYMBOL_ID: u32 = 14;
/// Approximate per-string heap footprint used for fail-closed budgeting.
const MEMORY_ESTIMATE_STRING_BASE_BYTES: u64 = 24;
/// Approximate per-heap-object base footprint.
const MEMORY_ESTIMATE_HEAP_OBJECT_BASE_BYTES: u64 = 64;
/// Approximate per-map-entry footprint.
const MEMORY_ESTIMATE_MAP_ENTRY_BYTES: u64 = 48;
/// Bound the stack-only source-owner deduplication in program preflights.
/// Owners beyond this small table remain conservatively charged per entry.
const MEMORY_ESTIMATE_FUNCTION_SOURCE_OWNERS: usize = 8;
/// Synthetic `ClosureHandle` id space for non-closure Promise reaction
/// callables (builtin functions, async/generator function objects). Real
/// closure ids stay far below this bound — each closure carries a tracked
/// memory charge, so the table cannot reach 2^31 entries under any budget —
/// and ids at or above the base index `promise_reaction_callables` instead
/// of the closure table.
const PROMISE_REACTION_CALLABLE_BASE: u32 = 0x8000_0000;

/// First id of a promise-value carrier (bd-9vouw.69). The promise subsystem
/// carries `JsValue`, which cannot express closures, generators, iterators,
/// promises, bound or builtin functions, BigInt or non-well-formed strings.
/// Such a value settles a promise as `JsValue::Function(id)`, with `id` at or
/// above this base naming an entry of `promise_value_carriers`. Function
/// indices of real modules never reach it, and guest code cannot name one.
const PROMISE_VALUE_CARRIER_BASE: u32 = 0xF000_0000;
/// Function index of a closure the collector reclaimed (bd-9vouw.57). No
/// function table is that large, so a call through a missed root fails.
const RECLAIMED_CLOSURE_FUNCTION_INDEX: u32 = u32::MAX;

/// Iteration traces are replay evidence (`ExecutionResult::iteration_traces`)
/// read by tests and cross-run comparisons of short programs. Each costs two
/// id derivations up front and one event (with derived value ids) per step,
/// uncharged by the memory budget, so recording is bounded: one trace per
/// `for...of` in a 1M-iteration loop reached 3 GB of RSS. Iterations past
/// `MAX_ITERATION_TRACES` are untraced; a trace stops recording events at
/// `MAX_ITERATION_TRACE_EVENTS`. Execution never depends on a trace.
const MAX_ITERATION_TRACES: usize = 1024;
const MAX_ITERATION_TRACE_EVENTS: usize = 4096;
/// Trace index of an untraced iteration.
const UNTRACED_ITERATION: usize = usize::MAX;
/// Most arrays one Array.prototype.join / toString may hold on its join
/// stack (nesting depth). The join keeps its nested arrays on an explicit
/// stack, so this bounds memory, not native stack: past it the join throws
/// RangeError ("Maximum call stack size exceeded"), as Node does somewhere
/// between 1,000 and 10,000 levels (bd-sxh8o.3, bd-9vouw.481).
const ARRAY_JOIN_MAX_DEPTH: usize = 10_000;
/// Nesting depth of the non-observable string fallback
/// ([`InterpreterCore::array_join_string`]), which recurses natively: deeper
/// sub-arrays render as `""` rather than risk stack exhaustion (bd-sxh8o.3).
const ARRAY_STRING_FALLBACK_MAX_DEPTH: usize = 128;

/// Append exact string units in linear space. Well-formed output keeps the
/// ordinary UTF-8 buffer; the first lone surrogate switches it to UTF-16.
#[derive(Default)]
struct ArrayJoinBuffer {
    text: String,
    units: Option<Vec<u16>>,
}

impl ArrayJoinBuffer {
    fn push(&mut self, value: &JsString) {
        if let Some(units) = &mut self.units {
            units.extend(value.encode_utf16());
        } else if let Some(text) = value.as_str() {
            self.text.push_str(text);
        } else {
            let mut units: Vec<u16> = self.text.encode_utf16().collect();
            units.extend(value.encode_utf16());
            self.text = String::new();
            self.units = Some(units);
        }
    }

    fn bytes(&self) -> u64 {
        self.units.as_ref().map_or(self.text.len() as u64, |units| {
            (units.len() as u64).saturating_mul(2)
        })
    }

    fn finish(self) -> JsString {
        self.units.map_or_else(
            || JsString::from(self.text),
            |units| JsString::from_code_units(&units),
        )
    }
}

/// One array of an Array.prototype.join in progress: its length, the next
/// element to render, and the exact string assembled so far.
struct ArrayJoinFrame {
    array_id: ObjectId,
    len: usize,
    index: usize,
    output: ArrayJoinBuffer,
}

impl ArrayJoinFrame {
    fn new(array_id: ObjectId, len: usize) -> Self {
        Self {
            array_id,
            len,
            index: 0,
            output: ArrayJoinBuffer::default(),
        }
    }
}

/// The register file of the synchronous reducer lane
/// ([`InterpreterCore::invoke_simple_reduce_callback_inner`]) and the bytes its
/// values own, kept up to date by each write: the lane used to re-sum every
/// register at every instruction. `high_water` is one past the highest
/// register written, the prefix to reset when the file goes back to the pool.
struct SimpleCallbackRegisters {
    values: Vec<Value>,
    value_bytes: u64,
    high_water: usize,
}

/// One queued `process.nextTick(callback, ...args)` job (bd-8nrud). The
/// callback runs with the forwarded arguments before any Promise microtask at
/// the next checkpoint, matching Node's next-tick ordering.
#[derive(Debug, Clone)]
struct NextTickTask {
    /// The callable to invoke (closure, plain function, or builtin).
    callback: Value,
    /// Arguments forwarded from the `process.nextTick` call site.
    args: Vec<Value>,
    /// IFC label joined over the registration arguments; the callback runs
    /// under this task label.
    label: Label,
}
/// Fixed instruction charge for authenticating and publishing one
/// `cluster.setupPrimary` replacement in addition to every property visited.
const CLUSTER_SETUP_FIXED_WORK: usize = 1;
/// Approximate per-scope-frame base footprint.
const MEMORY_ESTIMATE_SCOPE_FRAME_BASE_BYTES: u64 = 32;
/// Approximate per-scope-binding base footprint.
const MEMORY_ESTIMATE_SCOPE_BINDING_BASE_BYTES: u64 = 24;
/// Approximate per-closure base footprint.
const MEMORY_ESTIMATE_CLOSURE_BASE_BYTES: u64 = 32;
/// Approximate per-call-frame base footprint.
const MEMORY_ESTIMATE_CALL_FRAME_BASE_BYTES: u64 = 64;
/// Approximate per-iterator base footprint.
const MEMORY_ESTIMATE_ITERATOR_BASE_BYTES: u64 = 32;
/// Approximate per-generator base footprint.
const MEMORY_ESTIMATE_GENERATOR_BASE_BYTES: u64 = 48;
/// One shared owner-program handle retained by every suspended continuation.
const MEMORY_ESTIMATE_CONTINUATION_OWNER_BYTES: u64 = std::mem::size_of::<Arc<Ir3Module>>() as u64;
/// Conservative per-record charge for the emitter listener side table. The
/// event name and any string-backed listener payload are charged separately.
const MEMORY_ESTIMATE_EVENT_LISTENER_BASE_BYTES: u64 = 48;
/// Conservative fixed charge for one callable `once` wrapper's private state.
/// The map entry, event name, and original listener payload are charged
/// separately by `estimate_event_once_wrapper_state_bytes`.
const MEMORY_ESTIMATE_EVENT_ONCE_WRAPPER_BASE_BYTES: u64 = 48;
/// Conservative per-link charge for a Promise-backed `events.once` waiter.
/// A non-`error` wait registers two linked records (the awaited event and the
/// implicit rejection-on-`error` observer), both accounted independently.
const MEMORY_ESTIMATE_EVENT_PROMISE_WAITER_BASE_BYTES: u64 = 48;
/// Conservative fixed charges for the interpreter-local loopback `net`
/// kernel. The transport never creates an OS socket; these side tables own the
/// bounded server/socket lifecycle and queued byte payloads used by the Node
/// compatibility surface (bd-7qwej).
const MEMORY_ESTIMATE_LOOPBACK_SERVER_BASE_BYTES: u64 = 128;
const MEMORY_ESTIMATE_LOOPBACK_SOCKET_BASE_BYTES: u64 = 256;
const MEMORY_ESTIMATE_LOOPBACK_TASK_BASE_BYTES: u64 = 96;
const MEMORY_ESTIMATE_LOOPBACK_PORT_BASE_BYTES: u64 = 48;
/// Conservative fixed charges and hard guest-controlled ceilings for the
/// engine-owned HTTP/1.1 facade (bd-d0n7u). HTTP loopback retains request,
/// response, header, and queued lifecycle state outside the guest heap; these
/// bounds make every clone/allocation preflightable before publication.
const MEMORY_ESTIMATE_HTTP_SERVER_BASE_BYTES: u64 = 64;
const MEMORY_ESTIMATE_HTTP_CLIENT_REQUEST_BASE_BYTES: u64 = 192;
const MEMORY_ESTIMATE_HTTP_INCOMING_MESSAGE_BASE_BYTES: u64 = 160;
const MEMORY_ESTIMATE_HTTP_SERVER_RESPONSE_BASE_BYTES: u64 = 192;
const MEMORY_ESTIMATE_HTTP_TASK_BASE_BYTES: u64 = 80;
const MEMORY_ESTIMATE_HTTP_AGENT_BASE_BYTES: u64 = 48;
const MEMORY_ESTIMATE_HTTP_HEADER_ARRAY_BASE_BYTES: u64 = 24;
const MAX_HTTP_BODY_BYTES: usize = 1024 * 1024;
const DEFERRED_NETWORK_FLOW_POLICY_DENIAL: &str = "FLOW_POLICY_BLOCKED";
const MAX_HTTP_HEADER_COUNT: usize = 128;
const MAX_HTTP_HEADER_NAME_BYTES: usize = 256;
const MAX_HTTP_HEADER_VALUE_BYTES: usize = 8 * 1024;
const MAX_HTTP_PATH_BYTES: usize = 8 * 1024;
/// TLS ALPN identifiers are one-byte-length-prefixed, and the complete
/// ProtocolNameList is bounded by its u16 wire length. Enforce those protocol
/// bounds before iterating or allocating from a guest-controlled array-like.
const MAX_TLS_ALPN_PROTOCOL_BYTES: usize = u8::MAX as usize;
const MAX_TLS_ALPN_WIRE_BYTES: u64 = u16::MAX as u64;
/// The hermetic loopback surface accepts DNS/IP host strings only. Bounding
/// them to the maximum textual DNS name prevents attacker-sized host/SNI
/// clones before connection admission and metadata installation.
const MAX_LOOPBACK_HOST_BYTES: usize = 253;
/// Conservative base charge for one finite `Readable.from` side-table entry.
/// A retained string source and custom IFC label are charged separately.
const MEMORY_ESTIMATE_READABLE_FROM_BASE_BYTES: u64 = 64;
const MEMORY_ESTIMATE_READABLE_BUFFERED_CHUNK_BYTES: u64 = 32;
/// Additional retained side-table charge while `Readable.toArray()` waits for
/// the stream's terminal close phase before settling its Promise.
const MEMORY_ESTIMATE_READABLE_TO_ARRAY_WAITER_BYTES: u64 = 48;
/// Fixed charge retained after a Readable releases its live kernel. The
/// terminal lifecycle label is charged separately.
const MEMORY_ESTIMATE_READABLE_TERMINAL_BASE_BYTES: u64 = 64;
/// Conservative fixed charges for the engine-owned Writable kernel. Retained
/// strings and custom IFC-label names are charged separately.
// Fixed state-side charges include the inline state payload plus conservative
// map-entry bookkeeping. Keeping the live charge at least as large as the
// terminal charge lets a fully drained Writable terminalize at an exact budget
// ceiling without requiring fresh memory merely to preserve its tombstone.
const MEMORY_ESTIMATE_WRITABLE_BASE_BYTES: u64 = 512;
#[cfg(test)]
const MEMORY_ESTIMATE_WRITABLE_MAP_ENTRY_MARGIN_BYTES: usize = 64;
const WRITABLE_STATE_VIEW_KEYS: [&str; 10] = [
    "closed",
    "destroyed",
    "writable",
    "writableCorked",
    "writableEnded",
    "writableFinished",
    "writableHighWaterMark",
    "writableLength",
    "writableNeedDrain",
    "writableObjectMode",
];
/// Exact conservative charge for one node in the live Writable write FIFO.
/// Retained values, labels, callbacks, and callback provenance are charged
/// separately. A linked FIFO avoids the allocator-rounded spare capacity and
/// replacement-buffer peak of `VecDeque` growth at the memory ceiling.
const MEMORY_ESTIMATE_WRITABLE_WRITE_NODE_BYTES: u64 = 256;
/// Conservative fixed charge for a released Writable's authoritative terminal
/// state. The lifecycle label and any deferred post-close callbacks are
/// charged separately.
const MEMORY_ESTIMATE_WRITABLE_TERMINAL_BASE_BYTES: u64 = 192;
/// Exact conservative charge for one node in the terminal-callback linked
/// FIFO. Callback values, labels, and module provenance are charged separately.
const MEMORY_ESTIMATE_WRITABLE_END_CALLBACK_BYTES: u64 = 160;
/// BotGuard typed-array v1 per-buffer cap from bd-8enww.2.1.
const MAX_ARRAY_BUFFER_BYTE_LENGTH: u64 = 8 * 1024 * 1024;
/// Conservative workspace charge for zlib-rs's 32 KiB window, hash chains,
/// pending buffers, and wrapper state. The current pure-Rust deflater uses
/// roughly 311 KiB before caller-owned input/output storage.
const ZLIB_CODEC_WORKSPACE_BYTES: u64 = 512 * 1024;
const ZLIB_IO_CHUNK_BYTES: usize = 64 * 1024;
/// Conservative upper bound for the two heap metadata records and their
/// property strings published by one Buffer result. The exact allocator check
/// still runs before commit; this reserve makes the pre-codec operation-wide
/// peak proof independent of the eventual compressed length.
const ZLIB_PUBLICATION_METADATA_BYTES: u64 = 64 * 1024;
/// One deterministic instruction-budget unit per KiB of admitted codec work.
/// Compression additionally scales input work by the requested level, while
/// decompression reserves the full engine output cap before touching a codec.
const ZLIB_WORK_UNIT_BYTES: u64 = 1024;
/// Deterministic crypto inputs and outputs share Buffer's per-backing cap.
/// Stateful hash/cipher objects retain at most this much guest-controlled
/// material, and KDFs must prove their complete workspace below the global
/// memory ceiling before starting expensive work (bd-2z157).
const CRYPTO_MAX_INPUT_BYTES: usize = MAX_ARRAY_BUFFER_BYTE_LENGTH as usize;
const CRYPTO_STATE_BASE_BYTES: u64 = 192;
const CRYPTO_WORK_UNIT_BYTES: u64 = 1024;
/// One deterministic VM budget tick represents two scrypt ROMix block-mix
/// rounds. The complete ROMix plus both PBKDF2-phase work estimate is
/// separately capped before RustCrypto is invoked, so this calibration admits
/// Node's canonical N=16384,r=8 default under the 100k QuickJS budget without
/// restoring the former 128x undercharge.
const CRYPTO_SCRYPT_MIXES_PER_BUDGET_TICK: u64 = 2;
const CRYPTO_MAX_SCRYPT_WORK_UNITS: u64 = 1_000_000;
const CRYPTO_MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
/// Conservative metadata and encoded-string headroom for publishing a crypto
/// output. `encode_buffer_bytes` peaks at four bytes per source byte for its
/// UTF-16 path; unencoded Buffer publication is strictly below this bound.
const CRYPTO_OUTPUT_PUBLICATION_METADATA_BYTES: u64 = 4 * 1024;
/// One deterministic instruction-budget unit per KiB of HTTP framing, body,
/// or header materialization work, plus one unit per visited header/array item.
const HTTP_WORK_UNIT_BYTES: u64 = 1024;
/// Approximate metadata footprint for an ArrayBuffer-backed typed-array view.
const MEMORY_ESTIMATE_TYPED_ARRAY_VIEW_BYTES: u64 = 48;
/// Approximate metadata footprint for an ArrayBuffer-backed DataView.
const MEMORY_ESTIMATE_DATA_VIEW_BYTES: u64 = 40;
/// Offset for test-only synthetic function IDs to avoid production table IDs.
#[cfg(test)]
const TEST_FUNCTION_ID_OFFSET: u32 = 100_000;
/// Keep the common one-to-few loop-site case allocation-light and deterministic.
const JIT_LOOP_COUNTER_INLINE_CAPACITY: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostcallCapabilityClass {
    Runtime(RuntimeCapability),
    InternalAllowed,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ZlibFormat {
    Gzip,
    Zlib,
    Raw,
    Auto,
    Brotli,
}

enum ZlibOperationFailure {
    Data { code: &'static str, message: String },
    OutputLimit,
    Resource(InterpreterError),
}

impl From<InterpreterError> for ZlibOperationFailure {
    fn from(error: InterpreterError) -> Self {
        Self::Resource(error)
    }
}

impl ZlibOperationFailure {
    fn data(message: impl Into<String>) -> Self {
        Self::Data {
            code: "Z_DATA_ERROR",
            message: message.into(),
        }
    }

    fn need_dictionary(message: impl Into<String>) -> Self {
        Self::Data {
            code: "Z_NEED_DICT",
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CryptoHashAlgorithm {
    Md5,
    Sha1,
    Sha256,
    Sha512,
}

impl CryptoHashAlgorithm {
    fn parse(name: &str) -> Option<Self> {
        if name.eq_ignore_ascii_case("md5") {
            Some(Self::Md5)
        } else if name.eq_ignore_ascii_case("sha1") || name.eq_ignore_ascii_case("sha-1") {
            Some(Self::Sha1)
        } else if name.eq_ignore_ascii_case("sha256") || name.eq_ignore_ascii_case("sha-256") {
            Some(Self::Sha256)
        } else if name.eq_ignore_ascii_case("sha512") || name.eq_ignore_ascii_case("sha-512") {
            Some(Self::Sha512)
        } else {
            None
        }
    }

    fn output_len(self) -> usize {
        match self {
            Self::Md5 => 16,
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CryptoCipherAlgorithm {
    Aes256Cbc,
    Aes128Ctr,
    Aes256Gcm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CryptoCipherDirection {
    Encrypt,
    Decrypt,
}

type CryptoCipherOutput = (Zeroizing<Vec<u8>>, Option<Zeroizing<Vec<u8>>>);

/// Authenticated state for JS-visible crypto objects. No guest-writable heap
/// property participates in branding or lifecycle decisions: ObjectId
/// membership in `InterpreterCore::crypto_objects` is the authority.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CryptoObjectState {
    HashActive {
        algorithm: CryptoHashAlgorithm,
        input: Zeroizing<Vec<u8>>,
        lifecycle_label: Label,
    },
    HashFinalized {
        lifecycle_label: Label,
    },
    HmacActive {
        algorithm: CryptoHashAlgorithm,
        key: Zeroizing<Vec<u8>>,
        input: Zeroizing<Vec<u8>>,
        lifecycle_label: Label,
    },
    HmacFinalized {
        lifecycle_label: Label,
    },
    CipherActive {
        algorithm: CryptoCipherAlgorithm,
        direction: CryptoCipherDirection,
        key: Zeroizing<Vec<u8>>,
        iv: Zeroizing<Vec<u8>>,
        input: Zeroizing<Vec<u8>>,
        auth_tag: Option<Zeroizing<Vec<u8>>>,
        emitted: usize,
        output_encoding: Option<String>,
        output_remainder: Zeroizing<Vec<u8>>,
        lifecycle_label: Label,
    },
    CipherFinalized {
        algorithm: CryptoCipherAlgorithm,
        direction: CryptoCipherDirection,
        auth_tag: Option<Zeroizing<Vec<u8>>>,
        lifecycle_label: Label,
    },
    KeyPairActive {
        algorithm: CryptoKeyPairAlgorithm,
        private_key: Zeroizing<Vec<u8>>,
        public_key: Vec<u8>,
        lifecycle_label: Label,
    },
}

/// Asymmetric algorithms available to `crypto.generateKeyPairSync`
/// (bd-53l89; slice 3 adds NIST P-256 with RFC 6979 deterministic ECDSA).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CryptoKeyPairAlgorithm {
    Ed25519,
    EcP256,
}

impl CryptoObjectState {
    fn lifecycle_label(&self) -> &Label {
        match self {
            Self::HashActive {
                lifecycle_label, ..
            }
            | Self::HashFinalized { lifecycle_label }
            | Self::HmacActive {
                lifecycle_label, ..
            }
            | Self::HmacFinalized { lifecycle_label }
            | Self::CipherActive {
                lifecycle_label, ..
            }
            | Self::CipherFinalized {
                lifecycle_label, ..
            }
            | Self::KeyPairActive {
                lifecycle_label, ..
            } => lifecycle_label,
        }
    }

    fn supports_lifecycle_capability(&self, capability: &str) -> bool {
        match self {
            Self::HashActive { .. } | Self::HashFinalized { .. } => matches!(
                capability,
                "builtin:CryptoObjectUpdate"
                    | "builtin:CryptoObjectDigest"
                    | "builtin:CryptoObjectCopy"
            ),
            Self::HmacActive { .. } | Self::HmacFinalized { .. } => matches!(
                capability,
                "builtin:CryptoObjectUpdate" | "builtin:CryptoObjectDigest"
            ),
            Self::CipherActive {
                algorithm,
                direction,
                ..
            }
            | Self::CipherFinalized {
                algorithm,
                direction,
                ..
            } => match capability {
                "builtin:CryptoObjectUpdate" | "builtin:CryptoObjectFinal" => true,
                "builtin:CryptoObjectGetAuthTag" => {
                    *algorithm == CryptoCipherAlgorithm::Aes256Gcm
                        && *direction == CryptoCipherDirection::Encrypt
                }
                "builtin:CryptoObjectSetAuthTag" => {
                    *algorithm == CryptoCipherAlgorithm::Aes256Gcm
                        && *direction == CryptoCipherDirection::Decrypt
                }
                _ => false,
            },
            // bd-53l89 slice 1: a generated key pair exposes no lifecycle
            // methods yet; sign/verify dispatch arrives with its own slice and
            // will extend this arm. Until then every lifecycle capability is
            // refused, so the handle is inert by construction.
            Self::KeyPairActive { .. } => false,
        }
    }
}

/// Maximum length of a `capability_tag` byte slice that the witness /
/// decision log will record verbatim. Tags longer than this are still
/// gate-decided fail-closed (they cannot satisfy any known classifier),
/// but the recorded payload is truncated with a marker so a malicious
/// extension cannot inflate the audit log to arbitrary size via a single
/// long `HostCall` argument (bd-hxukn defense-in-depth).
const CAPABILITY_TAG_RECORD_BYTE_CAP: usize = 256;
/// Reserved prefix for a bounded capability-tag representation that commits
/// to the complete original tag with SHA-256. Inputs already using this
/// prefix are re-encoded so an ordinary short tag cannot impersonate the
/// representation of a different, overlong tag.
const CAPABILITY_TAG_DIGEST_PREFIX: &str = "<TRUNCATED:sha256:";
const IMPORT_META_URL_VALUE: &str = "frankenengine://module/import-meta";
const IMPORT_META_DIRNAME_VALUE: &str = "frankenengine://module/";

fn classify_hostcall_capability(tag: &str) -> HostcallCapabilityClass {
    match hostcall_registry_row(tag) {
        Some(row) => row.authority.map_or(
            HostcallCapabilityClass::InternalAllowed,
            HostcallCapabilityClass::Runtime,
        ),
        None => HostcallCapabilityClass::Unknown,
    }
}

/// Precomputed hostcall-dispatch decisions: the E9.T4 first activation
/// (bd-fqlfw.9.4), capability-pruned dispatch metadata.
///
/// Maps a constant hostcall capability tag to its allow/deny decision,
/// resolved once per run from the same live decision path the gate uses
/// ([`live_hostcall_decision`]), so the precomputed table and the live gate
/// cannot drift. The hot path consults the table first and falls through to
/// live classification on any miss (fail-closed per-call fallback). Witness
/// and decision-record emission is untouched, so execution values,
/// instruction counts, hostcall decision logs, and replay identity stay
/// byte-identical with and without the table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrunedHostcallDispatch {
    /// Schema version pin.
    pub schema_version: String,
    /// Deterministically ordered map: capability tag -> allowed decision.
    pub decisions: BTreeMap<String, bool>,
}

/// Schema version for [`PrunedHostcallDispatch`].
pub const PRUNED_HOSTCALL_DISPATCH_SCHEMA_VERSION: &str =
    "franken-engine.pruned-hostcall-dispatch.v1";

impl PrunedHostcallDispatch {
    /// Build a table from precomputed decisions.
    pub fn from_decisions(decisions: BTreeMap<String, bool>) -> Self {
        Self {
            schema_version: PRUNED_HOSTCALL_DISPATCH_SCHEMA_VERSION.to_string(),
            decisions,
        }
    }

    /// Precomputed decision for a tag, if resolved. `Some(true)` = allowed.
    pub fn lookup(&self, tag: &str) -> Option<bool> {
        self.decisions.get(tag).copied()
    }

    /// Number of resolved dispatch sites (distinct tags).
    pub fn resolved_count(&self) -> usize {
        self.decisions.len()
    }

    /// Canonical bytes for content-addressing the specialized artifact.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }
}

/// The live hostcall capability decision: `true` = allowed.
///
/// Shared `pub(crate)` with the E9.T4 activation builder
/// (`e9_first_activation`) so precomputed dispatch decisions are derived
/// from exactly this function and cannot drift from the gate — the same
/// discipline as the `instruction_cost` sharing with the E9.T1 discovery
/// lane.
pub(crate) fn live_hostcall_decision(tag: &str, granted: &BTreeSet<RuntimeCapability>) -> bool {
    match classify_hostcall_capability(tag) {
        HostcallCapabilityClass::Runtime(required) => granted.contains(&required),
        HostcallCapabilityClass::InternalAllowed => true,
        HostcallCapabilityClass::Unknown => false, // fail-closed on unknown tags
    }
}

fn builtin_prototype_capability_name(tag: &str) -> Option<&'static str> {
    tag.strip_prefix("builtin:proto:")
        .and_then(canonical_builtin_prototype_name)
}

pub(crate) fn builtin_instanceof_capability_name(tag: &str) -> Option<&'static str> {
    tag.strip_prefix("builtin:instanceof:")
        .and_then(canonical_builtin_prototype_name)
}

fn canonical_builtin_prototype_name(name: &str) -> Option<&'static str> {
    match name {
        "Object" => Some("Object"),
        "Function" => Some("Function"),
        "Array" => Some("Array"),
        "Map" => Some("Map"),
        "Set" => Some("Set"),
        "BigInt" => Some("BigInt"),
        "Number" => Some("Number"),
        "String" => Some("String"),
        "Boolean" => Some("Boolean"),
        "Symbol" => Some("Symbol"),
        "Error" => Some("Error"),
        "TypeError" => Some("TypeError"),
        "RangeError" => Some("RangeError"),
        "ReferenceError" => Some("ReferenceError"),
        "SyntaxError" => Some("SyntaxError"),
        "EvalError" => Some("EvalError"),
        "URIError" => Some("URIError"),
        "AggregateError" => Some("AggregateError"),
        "EventEmitter" => Some("EventEmitter"),
        "ArrayBuffer" => Some("ArrayBuffer"),
        "SharedArrayBuffer" => Some("SharedArrayBuffer"),
        "DataView" => Some("DataView"),
        "Int8Array" => Some("Int8Array"),
        "Uint8Array" => Some("Uint8Array"),
        "Uint8ClampedArray" => Some("Uint8ClampedArray"),
        "Int16Array" => Some("Int16Array"),
        "Uint16Array" => Some("Uint16Array"),
        "Int32Array" => Some("Int32Array"),
        "Uint32Array" => Some("Uint32Array"),
        "Float32Array" => Some("Float32Array"),
        "Float64Array" => Some("Float64Array"),
        "BigInt64Array" => Some("BigInt64Array"),
        "BigUint64Array" => Some("BigUint64Array"),
        // %TypedArray% (ES2020 22.2.1): not a global binding.
        "TypedArray" => Some("TypedArray"),
        "Date" => Some("Date"),
        "Promise" => Some("Promise"),
        "RegExp" => Some("RegExp"),
        "WeakMap" => Some("WeakMap"),
        "WeakSet" => Some("WeakSet"),
        "WeakRef" => Some("WeakRef"),
        "FinalizationRegistry" => Some("FinalizationRegistry"),
        "TextEncoder" => Some("TextEncoder"),
        "TextDecoder" => Some("TextDecoder"),
        "Buffer" => Some("Buffer"),
        "URL" => Some("URL"),
        "URLSearchParams" => Some("URLSearchParams"),
        "EventTarget" => Some("EventTarget"),
        "Event" => Some("Event"),
        "CustomEvent" => Some("CustomEvent"),
        "AbortController" => Some("AbortController"),
        "AbortSignal" => Some("AbortSignal"),
        "DOMException" => Some("DOMException"),
        "Blob" => Some("Blob"),
        // %GeneratorFunction%, %AsyncFunction%, %AsyncGeneratorFunction%:
        // not global bindings (FUNCTION_KIND_INTRINSICS).
        "GeneratorFunction" => Some("GeneratorFunction"),
        "AsyncFunction" => Some("AsyncFunction"),
        "AsyncGeneratorFunction" => Some("AsyncGeneratorFunction"),
        ITERATOR_PROTOTYPE => Some(ITERATOR_PROTOTYPE),
        // ES2025 27.1.3.1: the `Iterator` constructor's prototype is
        // %IteratorPrototype% (bd-9vouw.179).
        "Iterator" => Some(ITERATOR_PROTOTYPE),
        iterator_helpers::ITERATOR_HELPER_PROTOTYPE => {
            Some(iterator_helpers::ITERATOR_HELPER_PROTOTYPE)
        }
        iterator_helpers::WRAP_FOR_VALID_ITERATOR_PROTOTYPE => {
            Some(iterator_helpers::WRAP_FOR_VALID_ITERATOR_PROTOTYPE)
        }
        iterator_helpers::REGEXP_STRING_ITERATOR_PROTOTYPE => {
            Some(iterator_helpers::REGEXP_STRING_ITERATOR_PROTOTYPE)
        }
        ARRAY_ITERATOR_PROTOTYPE => Some(ARRAY_ITERATOR_PROTOTYPE),
        MAP_ITERATOR_PROTOTYPE => Some(MAP_ITERATOR_PROTOTYPE),
        SET_ITERATOR_PROTOTYPE => Some(SET_ITERATOR_PROTOTYPE),
        GENERATOR_PROTOTYPE => Some(GENERATOR_PROTOTYPE),
        ASYNC_GENERATOR_PROTOTYPE => Some(ASYNC_GENERATOR_PROTOTYPE),
        ASYNC_ITERATOR_PROTOTYPE => Some(ASYNC_ITERATOR_PROTOTYPE),
        _ => None,
    }
}

/// Borrow `tag` if it fits within [`CAPABILITY_TAG_RECORD_BYTE_CAP`] and does
/// not occupy the reserved digest namespace. Otherwise return a `Cow::Owned`
/// beginning with a SHA-256 commitment to the complete tag, followed by as
/// much UTF-8-safe display prefix as fits within the byte cap.
///
/// Prefixing the digest representation, and re-encoding inputs that already
/// start with [`CAPABILITY_TAG_DIGEST_PREFIX`], keeps the encoded and verbatim
/// domains disjoint. This prevents both overlong-prefix collisions and a
/// crafted short tag from impersonating an encoded long tag while preserving
/// ordinary short tags byte-for-byte (bd-hxukn, bd-lvoff).
fn recordable_capability_tag(tag: &str) -> std::borrow::Cow<'_, str> {
    use std::borrow::Cow;
    if tag.len() <= CAPABILITY_TAG_RECORD_BYTE_CAP && !tag.starts_with(CAPABILITY_TAG_DIGEST_PREFIX)
    {
        return Cow::Borrowed(tag);
    }

    let digest = ContentHash::compute(tag.as_bytes()).to_hex();
    let marker = format!("{CAPABILITY_TAG_DIGEST_PREFIX}{digest}>:");
    let prefix_len = CAPABILITY_TAG_RECORD_BYTE_CAP.saturating_sub(marker.len());
    // Walk back to the nearest UTF-8 char boundary so the prefix stays
    // a valid `&str` slice.
    let mut cut = prefix_len.min(tag.len());
    while cut > 0 && !tag.is_char_boundary(cut) {
        cut -= 1;
    }
    let mut out = String::with_capacity(marker.len() + cut);
    out.push_str(&marker);
    out.push_str(&tag[..cut]);
    debug_assert!(out.len() <= CAPABILITY_TAG_RECORD_BYTE_CAP);
    Cow::Owned(out)
}

/// The early SyntaxError of a regular expression literal (ES2020 12.2.8.1),
/// or `None` when it may be valid: duplicate or unknown flags, `u` with `v`,
/// a Unicode property escape with a name JavaScript does not define, or a
/// pattern that both the backtracking parser and the `regex` crate
/// reject. A pattern either one accepts is left to the runtime, which runs
/// it there, so no program that runs today is refused at parse time.
pub(crate) fn regexp_literal_early_error(pattern: &str, flags: &str) -> Option<String> {
    const FLAGS: &str = "dgimsuvy";
    let mut seen = [false; FLAGS.len()];
    let flags_valid = flags.chars().all(|flag| {
        FLAGS
            .find(flag)
            .is_some_and(|index| !std::mem::replace(&mut seen[index], true))
    }) && !(flags.contains('u') && flags.contains('v'));
    if !flags_valid {
        return Some(format!("Invalid regular expression flags '{flags}'"));
    }
    // Checked before any pass materializes the pattern (franken_engine#2);
    // the message does not echo a pattern this large.
    if pattern.len() > MAX_PATTERN_LEN {
        return Some(format!("Invalid regular expression: {PATTERN_TOO_LARGE}"));
    }
    // Property names are exact in JavaScript; the `regex` crate would accept
    // loose spellings (`\p{greek}`), so they are checked here.
    if let Some(message) = regexp_syntax::unicode_property_escape_error(pattern, flags) {
        return Some(format!(
            "Invalid regular expression: /{pattern}/{flags}: {message}"
        ));
    }
    // `regex` takes a `v` class's syntax characters, and a `u` or `v`
    // pattern's lone braces and class-escape range ends, as literals.
    let unicode_sets = flags.contains('v');
    let unicode_mode_error = (unicode_sets || flags.contains('u'))
        .then(|| regexp_syntax::unicode_mode_syntax_error(pattern, unicode_sets))
        .flatten();
    if let Some(message) = unicode_mode_error
        .or_else(|| {
            unicode_sets
                .then(|| regexp_syntax::unicode_sets_class_error(pattern))
                .flatten()
        })
        .or_else(|| regexp_syntax::group_modifier_error(pattern, unicode_sets))
    {
        return Some(format!(
            "Invalid regular expression: /{pattern}/{flags}: {message}"
        ));
    }
    let message = BacktrackRegExp::syntax_error(pattern, flags)?;
    let automaton_accepts = InterpreterCore::regexp_builder(pattern, flags)
        .is_ok_and(|builder| builder.build().is_ok());
    (!automaton_accepts)
        .then(|| format!("Invalid regular expression: /{pattern}/{flags}: {message}"))
}

/// Canonical key used by the live gate, decision/witness evidence, and E9's
/// pruned-dispatch table. The runtime accepts several route spellings for one
/// logical authority; they must retain one evidence identity or alias choice
/// can fragment policy and replay records.
pub(crate) fn capability_gate_key(tag: &str) -> &str {
    match tag {
        "module:require"
        | "module:import"
        | "module.import"
        | "module_load"
        | crate::capability::DYNAMIC_IMPORT_CAPABILITY => "module_load",
        "builtin:CryptoRandomBytes"
        | "builtin:CryptoRandomUUID"
        | "builtin:CryptoRandomInt"
        | "builtin:CryptoRandomFillSync" => "random_read",
        "env:read" | "env:has" => "env_read",
        crate::capability::FS_READ_PROMISE_CAPABILITY => "fs:read",
        _ => tag,
    }
}

// ---------------------------------------------------------------------------
// Node `path` builtin semantics (bd-tu0c3)
//
// Pure-compute string algorithms backing the `builtin:Path*` hostcalls emitted
// by the lowering pipeline's path-module interception. Posix semantics follow
// Node's `path.posix` implementation (the default `path` on linux IS posix);
// the win32 helpers cover the small separator-sensitive subset the lowering
// recognizes (join/basename/isAbsolute). Mirrored in
// `franken-core/src/baseline_interpreter.rs` (twin-lane convention, like the
// Math builtins) — keep the two copies in lockstep.
// ---------------------------------------------------------------------------

/// Resolve `.`/`..` segments of `path`: splits on `separators`, drops empty
/// and `.` segments, pops a stack entry for `..` (keeping leading `..`s only
/// when `allow_above_root`, i.e. for relative paths), then joins with `sep`.
/// Shared by normalize/join/resolve for both separator families.
fn node_path_normalize_segments(
    path: &str,
    allow_above_root: bool,
    sep: char,
    separators: &[char],
) -> String {
    let mut stack: Vec<&str> = Vec::new();
    for segment in path.split(|c: char| separators.contains(&c)) {
        if segment.is_empty() || segment == "." {
            continue;
        }
        if segment == ".." {
            match stack.last() {
                Some(&last) if last != ".." => {
                    stack.pop();
                }
                _ => {
                    if allow_above_root {
                        stack.push("..");
                    }
                }
            }
        } else {
            stack.push(segment);
        }
    }
    let mut out = String::new();
    for (index, segment) in stack.iter().enumerate() {
        if index > 0 {
            out.push(sep);
        }
        out.push_str(segment);
    }
    out
}

/// Node `path.posix.normalize`: dot-segment resolution, `//` collapse,
/// trailing-slash preservation; `''` -> `'.'`; leading `..` preserved for
/// relative paths and dropped above an absolute root.
fn node_path_posix_normalize(path: &str) -> String {
    if path.is_empty() {
        return ".".to_string();
    }
    let is_absolute = path.starts_with('/');
    let trailing_separator = path.ends_with('/');
    let mut normalized = node_path_normalize_segments(path, !is_absolute, '/', &['/']);
    if normalized.is_empty() {
        if is_absolute {
            return "/".to_string();
        }
        return if trailing_separator {
            "./".to_string()
        } else {
            ".".to_string()
        };
    }
    if trailing_separator {
        normalized.push('/');
    }
    if is_absolute {
        format!("/{normalized}")
    } else {
        normalized
    }
}

/// Node `path.posix.join`: empty segments dropped, joined with `/`, then
/// normalized; no segments (or all empty) -> `'.'`.
fn node_path_posix_join(parts: &[String]) -> String {
    let mut joined = String::new();
    for part in parts {
        if part.is_empty() {
            continue;
        }
        if !joined.is_empty() {
            joined.push('/');
        }
        joined.push_str(part);
    }
    if joined.is_empty() {
        return ".".to_string();
    }
    node_path_posix_normalize(&joined)
}

/// Node `path.posix.resolve` over pre-validated string segments: right-to-left
/// until an absolute segment wins, then normalize. The engine has NO ambient
/// cwd, so a FIXED synthetic cwd `"/"` is prefixed when no segment is absolute
/// — any consistent absolute base is behaviorally correct for pure-compute
/// resolution (the compat corpus asserts predicates over resolve()'s output,
/// never a host cwd value). The result never has a trailing slash unless it is
/// the root itself.
fn node_path_posix_resolve(parts: &[String]) -> String {
    let mut resolved = String::new();
    let mut resolved_absolute = false;
    let mut index = parts.len() as i64 - 1;
    while index >= -1 && !resolved_absolute {
        let segment: &str = if index >= 0 {
            parts[index as usize].as_str()
        } else {
            // Synthetic cwd (see doc comment above).
            "/"
        };
        index -= 1;
        if segment.is_empty() {
            continue;
        }
        resolved = format!("{segment}/{resolved}");
        resolved_absolute = segment.starts_with('/');
    }
    let normalized = node_path_normalize_segments(&resolved, !resolved_absolute, '/', &['/']);
    if resolved_absolute {
        format!("/{normalized}")
    } else if normalized.is_empty() {
        ".".to_string()
    } else {
        normalized
    }
}

/// Node `basename` shared across separator families: trailing separators
/// trimmed, last component returned, and `ext` stripped only when it is a
/// proper suffix strictly shorter than the basename (Node keeps `basename ==
/// ext` intact). `skip_win32_drive` skips a leading `X:` drive prefix (win32).
fn node_path_basename_impl(
    path: &str,
    ext: Option<&str>,
    separators: &[char],
    skip_win32_drive: bool,
) -> String {
    let mut p = path;
    if skip_win32_drive && p.len() >= 2 {
        let bytes = p.as_bytes();
        if bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
            p = &p[2..];
        }
    }
    let trimmed = p.trim_end_matches(|c: char| separators.contains(&c));
    let base = match trimmed.rfind(|c: char| separators.contains(&c)) {
        Some(index) => &trimmed[index + 1..],
        None => trimmed,
    };
    if let Some(ext) = ext
        && !ext.is_empty()
        && base.len() > ext.len()
        && base.ends_with(ext)
    {
        return base[..base.len() - ext.len()].to_string();
    }
    base.to_string()
}

/// Node `path.posix.dirname`: no trailing slash in the result, `'/'` -> `'/'`,
/// bare name -> `'.'`. Direct port of Node's end-scan (byte comparisons are
/// against ASCII `/`, so scanning UTF-8 bytes is boundary-safe).
fn node_path_posix_dirname(path: &str) -> String {
    if path.is_empty() {
        return ".".to_string();
    }
    let bytes = path.as_bytes();
    let has_root = bytes[0] == b'/';
    let mut end: i64 = -1;
    let mut matched_slash = true;
    let mut index = bytes.len() as i64 - 1;
    while index >= 1 {
        if bytes[index as usize] == b'/' {
            if !matched_slash {
                end = index;
                break;
            }
        } else {
            matched_slash = false;
        }
        index -= 1;
    }
    if end == -1 {
        return if has_root {
            "/".to_string()
        } else {
            ".".to_string()
        };
    }
    if has_root && end == 1 {
        return "//".to_string();
    }
    path[..end as usize].to_string()
}

/// Node `path.posix.extname`: the last `.`-suffix of the final component, with
/// Node's exact dotfile rules (`.bashrc` -> `''`, `file.` -> `'.'`, `..` ->
/// `''`). Direct port of Node's single-pass backward scan.
fn node_path_posix_extname(path: &str) -> String {
    let bytes = path.as_bytes();
    let mut start_dot: i64 = -1;
    let mut start_part: i64 = 0;
    let mut end: i64 = -1;
    let mut matched_slash = true;
    // Track the state of characters (if any) we see before our first dot and
    // after any path separator we find (Node's `preDotState`).
    let mut pre_dot_state: i64 = 0;
    let mut index = bytes.len() as i64 - 1;
    while index >= 0 {
        let code = bytes[index as usize];
        if code == b'/' {
            // Reached a path separator that was not part of a set of trailing
            // separators at the end of the string: stop.
            if !matched_slash {
                start_part = index + 1;
                break;
            }
            index -= 1;
            continue;
        }
        if end == -1 {
            // First non-separator from the end marks the end of the extension.
            matched_slash = false;
            end = index + 1;
        }
        if code == b'.' {
            if start_dot == -1 {
                start_dot = index;
            } else if pre_dot_state != 1 {
                pre_dot_state = 1;
            }
        } else if start_dot != -1 {
            // A non-dot character before the dot marks a real name part.
            pre_dot_state = -1;
        }
        index -= 1;
    }
    if start_dot == -1
        || end == -1
        // The dot(s) were the first character(s) of the component (dotfile) …
        || pre_dot_state == 0
        // … or the component is exactly `..`.
        || (pre_dot_state == 1 && start_dot == end - 1 && start_dot == start_part + 1)
    {
        return String::new();
    }
    path[start_dot as usize..end as usize].to_string()
}

/// Node `path.posix.relative` over resolved paths (same synthetic cwd as
/// [`node_path_posix_resolve`]): common-prefix segments dropped, `..` per
/// remaining `from` segment, then the remaining `to` segments.
fn node_path_posix_relative(from: &str, to: &str) -> String {
    let from_resolved = node_path_posix_resolve(std::slice::from_ref(&from.to_string()));
    let to_resolved = node_path_posix_resolve(std::slice::from_ref(&to.to_string()));
    if from_resolved == to_resolved {
        return String::new();
    }
    let from_segments: Vec<&str> = from_resolved.split('/').filter(|s| !s.is_empty()).collect();
    let to_segments: Vec<&str> = to_resolved.split('/').filter(|s| !s.is_empty()).collect();
    let mut common = 0usize;
    while common < from_segments.len()
        && common < to_segments.len()
        && from_segments[common] == to_segments[common]
    {
        common += 1;
    }
    let mut out_segments: Vec<&str> =
        std::iter::repeat_n("..", from_segments.len() - common).collect();
    out_segments.extend_from_slice(&to_segments[common..]);
    out_segments.join("/")
}

/// The `{ root, dir, base, ext, name }` decomposition of
/// [`node_path_posix_parse`].
struct NodePathParsed {
    root: String,
    dir: String,
    base: String,
    ext: String,
    name: String,
}

/// Node `path.posix.parse`: root/dir/base/ext/name decomposition. `base` uses
/// the basename rules (trailing slashes trimmed), `ext`/`name` use the extname
/// dotfile rules over `base`, `dir` is everything before the final component
/// (root for a root-only path, `''` for a bare name).
fn node_path_posix_parse(path: &str) -> NodePathParsed {
    if path.is_empty() {
        return NodePathParsed {
            root: String::new(),
            dir: String::new(),
            base: String::new(),
            ext: String::new(),
            name: String::new(),
        };
    }
    let root = if path.starts_with('/') { "/" } else { "" };
    let base = node_path_basename_impl(path, None, &['/'], false);
    let ext = node_path_posix_extname(&base);
    let name = base[..base.len() - ext.len()].to_string();
    let trimmed = path.trim_end_matches('/');
    let dir = match trimmed.rfind('/') {
        Some(0) => "/".to_string(),
        Some(index) => trimmed[..index].to_string(),
        None => root.to_string(),
    };
    NodePathParsed {
        root: root.to_string(),
        dir,
        base,
        ext,
        name,
    }
}

/// Node `path.posix.format`: `dir`+`base` win over `root`+`name`+`ext`
/// (`base` wins over `name`+`ext`; an extension without a leading dot gets
/// one). Empty-string properties count as absent, matching JS truthiness in
/// Node's `_format`.
fn node_path_posix_format(root: &str, dir: &str, base: &str, name: &str, ext: &str) -> String {
    let dir_part = if dir.is_empty() { root } else { dir };
    let formatted_ext = if ext.is_empty() {
        String::new()
    } else if ext.starts_with('.') {
        ext.to_string()
    } else {
        format!(".{ext}")
    };
    let base_part = if base.is_empty() {
        format!("{name}{formatted_ext}")
    } else {
        base.to_string()
    };
    if dir_part.is_empty() {
        return base_part;
    }
    if dir_part == root {
        format!("{dir_part}{base_part}")
    } else {
        format!("{dir_part}/{base_part}")
    }
}

/// Node `path.win32.isAbsolute`: a leading separator (either kind, incl. UNC)
/// or a drive letter followed by `:` and a separator.
fn node_path_win32_is_absolute(path: &str) -> bool {
    let bytes = path.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    if bytes[0] == b'/' || bytes[0] == b'\\' {
        return true;
    }
    bytes.len() > 2
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'/' || bytes[2] == b'\\')
}

/// Node `path.win32.normalize`: both separators accepted, output uses `\`.
/// Handles drive-letter roots (`C:\`, drive-relative `C:x`), UNC roots
/// (`\\server\share`), and bare separator roots; `\\?\`-style device
/// namespaces are not modeled (outside the recognized corpus surface).
fn node_path_win32_normalize(path: &str) -> String {
    if path.is_empty() {
        return ".".to_string();
    }
    let bytes = path.as_bytes();
    let is_sep = |b: u8| b == b'/' || b == b'\\';
    let mut device = String::new();
    let mut is_absolute = false;
    let mut root_len = 0usize;
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        device.push(bytes[0] as char);
        device.push(':');
        root_len = 2;
        if bytes.len() > 2 && is_sep(bytes[2]) {
            is_absolute = true;
            root_len = 3;
        }
    } else if is_sep(bytes[0]) {
        is_absolute = true;
        root_len = 1;
        if bytes.len() > 1 && is_sep(bytes[1]) {
            // Candidate UNC root: `\\server\share`.
            let mut cursor = 2usize;
            let server_start = cursor;
            while cursor < bytes.len() && !is_sep(bytes[cursor]) {
                cursor += 1;
            }
            if cursor > server_start && cursor < bytes.len() {
                let server_end = cursor;
                while cursor < bytes.len() && is_sep(bytes[cursor]) {
                    cursor += 1;
                }
                let share_start = cursor;
                while cursor < bytes.len() && !is_sep(bytes[cursor]) {
                    cursor += 1;
                }
                if cursor > share_start {
                    device = format!(
                        "\\\\{}\\{}",
                        &path[server_start..server_end],
                        &path[share_start..cursor]
                    );
                    root_len = cursor;
                }
            }
        }
    }
    let tail = &path[root_len..];
    let trailing_separator = tail.ends_with(['/', '\\']);
    let mut normalized = node_path_normalize_segments(tail, !is_absolute, '\\', &['/', '\\']);
    if normalized.is_empty() && !is_absolute {
        normalized.push('.');
    }
    if trailing_separator {
        normalized.push('\\');
    }
    if is_absolute {
        format!("{device}\\{normalized}")
    } else {
        format!("{device}{normalized}")
    }
}

/// Node `path.win32.join`: empty segments dropped, joined with `\`, Node's
/// UNC-safety heuristic applied (a joined result must not ACCIDENTALLY read as
/// UNC unless the first part already matched a UNC root), then win32
/// normalization.
fn node_path_win32_join(parts: &[String]) -> String {
    let mut joined = String::new();
    let mut first_part: Option<&str> = None;
    for part in parts {
        if part.is_empty() {
            continue;
        }
        if joined.is_empty() {
            first_part = Some(part.as_str());
            joined.push_str(part);
        } else {
            joined.push('\\');
            joined.push_str(part);
        }
    }
    if joined.is_empty() {
        return ".".to_string();
    }
    let is_sep = |b: u8| b == b'/' || b == b'\\';
    let first_bytes = first_part.unwrap_or("").as_bytes();
    let mut needs_replace = true;
    let mut slash_count = 0usize;
    if !first_bytes.is_empty() && is_sep(first_bytes[0]) {
        slash_count += 1;
        if first_bytes.len() > 1 && is_sep(first_bytes[1]) {
            slash_count += 1;
            if first_bytes.len() > 2 {
                if is_sep(first_bytes[2]) {
                    slash_count += 1;
                } else {
                    // The first part matched a UNC root (`\\server`); keep it.
                    needs_replace = false;
                }
            }
        }
    }
    if needs_replace {
        let joined_bytes = joined.as_bytes();
        while slash_count < joined_bytes.len() && is_sep(joined_bytes[slash_count]) {
            slash_count += 1;
        }
        if slash_count >= 2 {
            joined = format!("\\{}", &joined[slash_count..]);
        }
    }
    node_path_win32_normalize(&joined)
}

// ---------------------------------------------------------------------------
// Node `querystring` builtin semantics (bd-qmy52)
//
// Pure-compute string algorithms backing the `builtin:Querystring*` hostcalls
// emitted by the lowering pipeline's querystring-module interception. Escape/
// unescape/parse edge behaviors are pinned against bun 1.3.14 (Node-compatible
// reference). Mirrored in `franken-core/src/baseline_interpreter.rs`
// (twin-lane convention, like the path builtins) — keep the two copies in
// lockstep.
// ---------------------------------------------------------------------------

/// Characters Node's `querystring.escape` leaves literal (the `noEscape`
/// table): ASCII alphanumerics plus `- . _ ~ ! ' ( ) *`. Everything else —
/// including space and `+` — percent-encodes.
fn qs_is_unescaped_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~' | '!' | '\'' | '(' | ')' | '*')
}

/// Node `querystring.escape`: percent-encode every char outside the noEscape
/// set as uppercase-hex UTF-8 bytes (bun: space -> `%20`, `+` -> `%2B`,
/// `é` -> `%C3%A9`, `中` -> `%E4%B8%AD`).
fn node_qs_escape(input: &str) -> String {
    const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(input.len());
    let mut utf8_buf = [0u8; 4];
    for c in input.chars() {
        if qs_is_unescaped_char(c) {
            out.push(c);
        } else {
            for byte in c.encode_utf8(&mut utf8_buf).as_bytes() {
                out.push('%');
                out.push(char::from(HEX_UPPER[(byte >> 4) as usize]));
                out.push(char::from(HEX_UPPER[(byte & 0x0f) as usize]));
            }
        }
    }
    out
}

/// Hex digit value of an ASCII byte (Node's `isHexTable` accepts both cases).
fn qs_hex_digit_value(byte: u8) -> Option<u8> {
    (byte as char).to_digit(16).map(|digit| digit as u8)
}

/// Strict percent-decode matching the `decodeURIComponent` accept set Node's
/// `querystring.unescape` tries first: every `%` must be followed by two hex
/// digits and the decoded byte sequence must be valid UTF-8; `+` is NOT
/// decoded. `None` on any violation (the caller falls back to the lenient
/// `unescapeBuffer` semantics).
fn qs_strict_percent_decode(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hi = qs_hex_digit_value(*bytes.get(index + 1)?)?;
            let lo = qs_hex_digit_value(*bytes.get(index + 2)?)?;
            out.push((hi << 4) | lo);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Lenient fallback matching Node's `unescapeBuffer`: valid `%XX` pairs decode
/// byte-wise, malformed `%` sequences stay literal, and the byte buffer is
/// decoded as UTF-8 with U+FFFD replacement (bun: `qs.unescape('%FF')` is
/// `'\u{FFFD}'`, `qs.unescape('a%2')` is `'a%2'`).
fn qs_lenient_unescape(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && let (Some(hi), Some(lo)) = (
                bytes.get(index + 1).copied().and_then(qs_hex_digit_value),
                bytes.get(index + 2).copied().and_then(qs_hex_digit_value),
            )
        {
            out.push((hi << 4) | lo);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Node `querystring.unescape`: try the strict `decodeURIComponent`-shaped
/// decode first, fall back to the lenient `unescapeBuffer` semantics on any
/// malformed input. `+` never decodes to space here — only `parse`'s component
/// handling does that (bun: `qs.unescape('x+y')` is `'x+y'`).
fn node_qs_unescape(input: &str) -> String {
    match qs_strict_percent_decode(input) {
        Some(decoded) => decoded,
        None => qs_lenient_unescape(input),
    }
}

/// True when `raw` contains at least one complete valid `%XX` escape — Node's
/// parse routes a key/value through the decoder only when its scanner saw a
/// full valid escape (`keyEncoded`/`valEncoded`), so `'a%2'` stays literal.
fn qs_component_looks_encoded(raw: &str) -> bool {
    raw.as_bytes().windows(3).any(|window| {
        window[0] == b'%'
            && qs_hex_digit_value(window[1]).is_some()
            && qs_hex_digit_value(window[2]).is_some()
    })
}

/// Decode one `parse` component: `+` becomes space FIRST (Node's `plusChar`
/// substitution precedes decoding), then the unescape pass runs only when the
/// raw component contained a complete valid `%XX` escape.
fn qs_parse_component(raw: &str) -> String {
    let plussed = raw.replace('+', " ");
    if qs_component_looks_encoded(raw) {
        node_qs_unescape(&plussed)
    } else {
        plussed
    }
}

/// Node `querystring.parse` over a pre-validated input string: split on `sep`,
/// the FIRST `eq` in a segment splits key/value (a key without `eq` maps to
/// `''`), `max_pairs` slots (default 1000, `None` = unlimited) are consumed by
/// stored pairs AND by empty segments between separators (bun:
/// `parse('&a=1', null, null, { maxKeys: 1 })` is `{}` but a TRAILING empty
/// segment is a no-op: `parse('a=1&')` is `{ a: '1' }`), and repeated keys
/// collect into arrays. Returns entries in first-seen key order with per-key
/// value order preserved; keys with one value are scalars at allocation.
fn node_qs_parse(
    input: &str,
    sep: &str,
    eq: &str,
    max_pairs: Option<u64>,
) -> Vec<(String, Vec<String>)> {
    let mut entries: Vec<(String, Vec<String>)> = Vec::new();
    if input.is_empty() {
        return entries;
    }
    // A truthy custom separator can stringify to '' (e.g. `[]`); Node's
    // char-code matcher then never matches, i.e. no splitting occurs. Same
    // for an empty `eq`: the whole segment becomes the key.
    let segments: Vec<&str> = if sep.is_empty() {
        vec![input]
    } else {
        input.split(sep).collect()
    };
    let last_index = segments.len() - 1;
    let mut remaining = max_pairs;
    for (index, segment) in segments.iter().enumerate() {
        if segment.is_empty() {
            // Empty segment BETWEEN separators: consumes a pair slot without
            // storing anything (Node decrements `pairs`); trailing is a no-op.
            if index < last_index
                && let Some(slots) = remaining.as_mut()
            {
                *slots -= 1;
                if *slots == 0 {
                    return entries;
                }
            }
            continue;
        }
        let (raw_key, raw_value) = if eq.is_empty() {
            (*segment, None)
        } else {
            match segment.find(eq) {
                Some(pos) => (&segment[..pos], Some(&segment[pos + eq.len()..])),
                None => (*segment, None),
            }
        };
        let key = qs_parse_component(raw_key);
        let value = raw_value.map(qs_parse_component).unwrap_or_default();
        match entries.iter_mut().find(|(existing, _)| *existing == key) {
            Some((_, values)) => values.push(value),
            None => entries.push((key, vec![value])),
        }
        if let Some(slots) = remaining.as_mut() {
            *slots -= 1;
            if *slots == 0 {
                return entries;
            }
        }
    }
    entries
}

// ---------------------------------------------------------------------------
// Node `os` builtin fixed values (bd-qmy52)
//
// The engine has NO ambient authority: the `builtin:Os*` hostcalls return
// FIXED, deterministic, linux-shaped engine-contained values (they never read
// the real host). The compat corpus asserts types and predicates (e.g.
// `typeof os.hostname() === 'string'`, `os.freemem() <= os.totalmem()`), not
// host facts, so any internally-consistent value set is behaviorally correct.
// Mirrored in `franken-core/src/baseline_interpreter.rs` — keep in lockstep.
// ---------------------------------------------------------------------------

/// `os.platform()` — also mirrored by the injected `process.platform` shape
/// value so `os.platform() === process.platform` holds (Node/linux).
const NODE_OS_PLATFORM: &str = "linux";
/// `os.arch()` — also exposed by the granted `process.arch` shape read.
const NODE_OS_ARCH: &str = "x64";
/// `os.release()` — fixed plausible kernel release string.
const NODE_OS_RELEASE: &str = "6.0.0-franken";
/// `os.version()` — fixed plausible kernel version string.
const NODE_OS_VERSION: &str = "#1 SMP PREEMPT_DYNAMIC franken";
/// `os.totalmem()` — fixed 16 GiB.
const NODE_OS_TOTALMEM_BYTES: i64 = 17_179_869_184;
/// `os.freemem()` — fixed 8 GiB (strictly below [`NODE_OS_TOTALMEM_BYTES`]).
const NODE_OS_FREEMEM_BYTES: i64 = 8_589_934_592;

/// POSIX signal numbers for `os.constants.signals` (linux, x86-64 numbering).
const NODE_OS_SIGNALS: &[(&str, i64)] = &[
    ("SIGHUP", 1),
    ("SIGINT", 2),
    ("SIGQUIT", 3),
    ("SIGILL", 4),
    ("SIGTRAP", 5),
    ("SIGABRT", 6),
    ("SIGBUS", 7),
    ("SIGFPE", 8),
    ("SIGKILL", 9),
    ("SIGUSR1", 10),
    ("SIGSEGV", 11),
    ("SIGUSR2", 12),
    ("SIGPIPE", 13),
    ("SIGALRM", 14),
    ("SIGTERM", 15),
    ("SIGCHLD", 17),
    ("SIGCONT", 18),
    ("SIGSTOP", 19),
    ("SIGTSTP", 20),
];

/// POSIX errno numbers for `os.constants.errno` (linux).
const NODE_OS_ERRNO: &[(&str, i64)] = &[
    ("EPERM", 1),
    ("ENOENT", 2),
    ("ESRCH", 3),
    ("EINTR", 4),
    ("EIO", 5),
    ("EBADF", 9),
    ("EAGAIN", 11),
    ("ENOMEM", 12),
    ("EACCES", 13),
    ("EFAULT", 14),
    ("EBUSY", 16),
    ("EEXIST", 17),
    ("ENOTDIR", 20),
    ("EISDIR", 21),
    ("EINVAL", 22),
    ("ENFILE", 23),
    ("EMFILE", 24),
    ("ENOSPC", 28),
    ("ESPIPE", 29),
    ("EROFS", 30),
    ("EPIPE", 32),
    ("ERANGE", 34),
];

/// `os.constants.priority` values (Node's uv priority constants).
const NODE_OS_PRIORITY: &[(&str, i64)] = &[
    ("PRIORITY_LOW", 19),
    ("PRIORITY_BELOW_NORMAL", 10),
    ("PRIORITY_NORMAL", 0),
    ("PRIORITY_ABOVE_NORMAL", -7),
    ("PRIORITY_HIGH", -14),
    ("PRIORITY_HIGHEST", -20),
];

/// Map an [`InterpreterError`] to a small stable `u32` for the telemetry
/// schema's `HostcallResult::Error { code }` field. Codes are an internal
/// taxonomy (not user-visible) and are intentionally narrow so a new error
/// variant added later falls into the catch-all bucket rather than silently
/// reusing an unrelated code.
fn interpreter_error_telemetry_code(err: &InterpreterError) -> u32 {
    match err {
        InterpreterError::CapabilityDenied { .. } => 1,
        InterpreterError::TypeError { .. } => 2,
        InterpreterError::RangeError { .. } => 3,
        InterpreterError::RegisterOutOfBounds { .. } => 4,
        InterpreterError::PropertyNotFound { .. } => 5,
        InterpreterError::ObjectNotFound { .. } => 6,
        InterpreterError::DivisionByZero => 7,
        InterpreterError::BudgetExhausted { .. } => 8,
        InterpreterError::MemoryBudgetExceeded { .. } => 9,
        InterpreterError::UncaughtException { .. } => 10,
        InterpreterError::ModuleResolutionFailed { .. }
        | InterpreterError::ModuleReadFailed { .. }
        | InterpreterError::ModuleParseFailed { .. }
        | InterpreterError::ModuleLoweringFailed { .. }
        | InterpreterError::ModuleEvaluationFailed { .. } => 11,
        InterpreterError::RequireSpecifierNotString { .. }
        | InterpreterError::ImportSpecifierNotString { .. } => 12,
        _ => 0,
    }
}

/// Map an [`InterpreterError`] to a short, stable string code for the
/// generated-code audit trail (bd-8enww.3.4 / YTBG-C4). Deterministic across
/// runs and free of variable/adversarial payload text, so the audit `outcome`
/// stays a clean fault classification rather than embedding hostile thrown
/// content. A new error variant added later falls into the catch-all bucket.
fn generated_code_fault_code(err: &InterpreterError) -> &'static str {
    match err {
        InterpreterError::CapabilityDenied { .. } => "capability_denied",
        InterpreterError::BudgetExhausted { .. } => "budget_exhausted",
        InterpreterError::MemoryBudgetExceeded { .. } => "memory_budget_exceeded",
        InterpreterError::UncaughtException { .. } => "uncaught_exception",
        InterpreterError::TypeError { .. } => "type_error",
        InterpreterError::RangeError { .. } => "range_error",
        _ => "error",
    }
}

/// Whether a hostcall has no external host effect: its registry authority is
/// `Builtin` (a computation over guest values) or none, or it enqueues a
/// deterministic guest microtask. Repeated grants can be counted instead of
/// retained. Microtask enqueues additionally commit their exact callable and
/// execution position to the IR4 witness; Timer authority remains mandatory.
fn hostcall_is_effect_free(tag: &str) -> bool {
    tag != crate::capability::UTIL_PROCESS_ARGV_CAPABILITY
        && tag != crate::capability::UTIL_PROCESS_EXEC_ARGV_CAPABILITY
        && (tag == "builtin:QueueMicrotask"
            || hostcall_registry_row(tag).is_some_and(|row| {
                matches!(row.authority, None | Some(RuntimeCapability::Builtin))
            }))
}

/// Shared capability gate logic for both Call and HostCall instructions.
/// Checks if the given capability is allowed and records witness events/decisions.
/// Returns whether a decision was recorded; a caller records the dispatch
/// witness only then.
fn check_hostcall_capability_gate(
    interpreter: &mut InterpreterCore,
    capability_tag: &str,
    instruction_index: u32,
) -> Result<bool, InterpreterError> {
    // Keep the operation spelling for the live hook: an exact witness denial
    // of env:read must still match even though its authority/evidence key is
    // env_read. The native Promise read changes only completion of the SAME
    // fs:read effect, so existing exact read policies must still observe it.
    // Its distinct IR tag remains available for dispatch and result contracts.
    let operation_tag = match capability_tag {
        crate::capability::FS_READ_PROMISE_CAPABILITY => "fs:read",
        other => other,
    };
    let capability_tag = capability_gate_key(operation_tag);
    // bd-9vouw.76: a language operation encoded as a HostCall needs no
    // authority. Recording its constant `allowed` decision per call grew the
    // witness and decision log by one entry per destructuring step.
    if is_language_operation_tag(capability_tag) {
        return Ok(false);
    }
    // E9.T4 (bd-fqlfw.9.4): consult the capability-pruned dispatch table
    // first when one is installed; any miss falls through to the live
    // classification (fail-closed per-call fallback). Only the allow/deny
    // bit is precomputed — every witness and decision-record emission below
    // is identical on both paths.
    let capability_denied = (matches!(
        operation_tag,
        crate::capability::UTIL_PROCESS_ARGV_CAPABILITY
            | crate::capability::UTIL_PROCESS_EXEC_ARGV_CAPABILITY
    ) && !interpreter.config.process_shape_read_allowed)
        || match interpreter
            .pruned_hostcall_dispatch
            .as_ref()
            .and_then(|table| table.lookup(capability_tag))
        {
            Some(allowed) => !allowed,
            None => {
                !live_hostcall_decision(capability_tag, &interpreter.config.granted_capabilities)
            }
        };

    // bd-hxukn: cap the tag length at the recording sites so an attacker
    // who controls the `HostCall` capability string cannot inflate the
    // witness or decision log with a multi-megabyte payload per call.
    let recordable_tag = recordable_capability_tag(capability_tag);

    // Observe the actual authority decision before dispatch, including calls
    // through builtin values and ApplyHostCall. Property/call hooks alone do
    // not cover these paths. A capability denial remains the primary error;
    // the hook cannot grant authority or suppress its denial evidence.
    let hook_action = interpreter.hook.as_ref().map(|hook| {
        let recordable_operation = recordable_capability_tag(operation_tag);
        hook.pre_hostcall(
            &HookContext {
                extension_id: interpreter
                    .config
                    .extension_id
                    .clone()
                    .unwrap_or_else(|| "extension:current".to_string()),
                instruction_count: interpreter.instructions_executed,
                current_ip: instruction_index as usize,
            },
            recordable_operation.as_ref(),
            !capability_denied,
        )
    });

    if capability_denied {
        interpreter
            .recorded_effect_free_grants
            .remove(recordable_tag.as_ref());
        interpreter.emit_witness(
            WitnessEventKind::CapabilityChecked,
            Some(&format!("denied:{}", recordable_tag)),
        );
        interpreter.hostcall_decisions.push(HostcallDecisionRecord {
            seq: interpreter.hostcall_decisions.len() as u64,
            capability: CapabilityTag(recordable_tag.clone().into_owned()),
            allowed: false,
            instruction_index,
        });
        // Feed the mandatory runtime security observability surface from the
        // real failure site: the live capability gate. The denial here is an
        // authority gap (the required capability is absent from the granted
        // set, or the tag is unknown and fails closed), which maps to
        // `InsufficientAuthority`.
        let denial_context = interpreter.capability_denial_event_context(instruction_index);
        interpreter.security_observability.record_capability_denial(
            denial_context,
            CapabilityDenialReason::InsufficientAuthority,
            recordable_tag.as_ref(),
        );
        return Err(InterpreterError::CapabilityDenied {
            capability: recordable_tag.into_owned(),
        });
    }

    if let Some(action) = hook_action {
        interpreter.enforce_hook_action(action)?;
    }

    // bd-9vouw.83: an effect-free hostcall in a loop (`JSON.stringify`,
    // `Object.keys`, `parseInt`, `String.fromCharCode`) repeated its tag's
    // last recorded grant on every call, two witness events and one decision
    // per call for the whole run. Count the repeat instead. The first grant
    // per tag and the first grant after a denial stay recorded, so every
    // change of decision is in the log; denials and hostcalls with host
    // effects record every call.
    if hostcall_is_effect_free(capability_tag) {
        if interpreter
            .recorded_effect_free_grants
            .contains(recordable_tag.as_ref())
        {
            interpreter.folded_hostcall_decisions =
                interpreter.folded_hostcall_decisions.saturating_add(1);
            return Ok(false);
        }
        interpreter
            .recorded_effect_free_grants
            .insert(recordable_tag.clone().into_owned());
    }

    // Record successful capability grant
    interpreter.emit_witness(
        WitnessEventKind::CapabilityChecked,
        Some(&format!("granted:{}", recordable_tag)),
    );
    interpreter.hostcall_decisions.push(HostcallDecisionRecord {
        seq: interpreter.hostcall_decisions.len() as u64,
        capability: CapabilityTag(recordable_tag.into_owned()),
        allowed: true,
        instruction_index,
    });

    Ok(true)
}

/// Canonical operator-facing label for the deterministic execution profile.
pub const DETERMINISTIC_PROFILE_LABEL: &str = "baseline_deterministic_profile";
/// Canonical operator-facing label for the throughput execution profile.
pub const THROUGHPUT_PROFILE_LABEL: &str = "baseline_throughput_profile";
/// Legacy lineage label still accepted on input for the deterministic profile.
pub const LEGACY_QUICKJS_PROFILE_LABEL: &str = "quickjs_inspired_native";
/// Legacy lineage label still accepted on input for the throughput profile.
pub const LEGACY_V8_PROFILE_LABEL: &str = "v8_inspired_native";

// ---------------------------------------------------------------------------
// Float64 — Deterministic f64 wrapper with total ordering
// ---------------------------------------------------------------------------

/// Active timer record for setTimeout/setInterval tracking and cancellation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveTimer {
    /// The handler to invoke when the timer fires.
    pub handler: Option<u32>,
    /// The delay in milliseconds.
    pub delay_ms: u64,
    /// For setInterval, whether this timer repeats.
    pub repeating: bool,
}

/// bd-suwvw: `__type` marker for setTimeout/setInterval handle objects.
const TIMER_HANDLE_TIMEOUT_TYPE: &str = "Timeout";
/// bd-suwvw: `__type` marker for setImmediate handle objects.
const TIMER_HANDLE_IMMEDIATE_TYPE: &str = "Immediate";
/// bd-suwvw: `__type` marker for the timers/promises setInterval iterable.
const TIMERS_PROMISES_INTERVAL_TYPE: &str = "TimersPromisesInterval";

/// bd-suwvw: what a scheduled timer/immediate macrotask does when it fires,
/// keyed by the macrotask's registration sequence (side table on the
/// interpreter, mirroring `pending_io_callbacks`). Carries the cancellation
/// link (`timer_id` — the macrotask is skipped if the id is no longer in
/// `active_timers`), the stashed extra callback arguments
/// (`setTimeout(cb, ms, ...args)`), and the interval re-scheduling recipe.
#[derive(Debug, Clone)]
struct PendingTimerTask {
    /// The user-visible timer id this macrotask belongs to; the entry in
    /// `active_timers` under this id is the cancellation authority.
    timer_id: u32,
    kind: PendingTimerTaskKind,
}

/// A filesystem Promise settles in the same I/O lane as the facade's callback.
/// The map retains both values until adoption/rejection finishes, including
/// observable thenable lookup on a returned Buffer.
#[derive(Debug, Clone)]
struct PendingFsPromiseRead {
    promise: crate::promise_model::PromiseHandle,
    outcome: Result<Value, Value>,
}

/// A host module job owns the caller's resolution and IFC context until its
/// deterministic I/O turn. The retained program is shared with the module
/// registry; the result Promise stays rooted even if the guest discards it.
#[derive(Debug, Clone)]
struct PendingDynamicImportTask {
    owner_module: Arc<Ir3Module>,
    referrer: String,
    specifier: String,
    promise: crate::promise_model::PromiseHandle,
    label: Label,
    cjs_context: Option<CjsModuleContext>,
    inline_context_label: Option<Label>,
    source_ip: usize,
}

#[derive(Debug, Clone)]
enum PendingTimerTaskKind {
    /// A JS callback timer (`setTimeout`/`setInterval`/`setImmediate`).
    Callback {
        /// Exact callable supplied by the guest. Retaining the full value makes
        /// named `Function` callbacks real rather than registering a handle with
        /// no delivery task.
        callback: Value,
        /// Extra trailing arguments forwarded to the callback on every fire.
        args: Vec<Value>,
        /// `setInterval` timers re-schedule themselves after each fire while
        /// still active.
        repeating: bool,
        /// The (already clamped) per-fire delay used for re-scheduling.
        delay_ms: u64,
        /// IFC label joined from the callback, delay, and extra arguments at
        /// registration. Delivery reuses this exact label on every interval tick.
        label: Label,
    },
    /// A `require('timers/promises')` timer: fulfills `promise` with `value`
    /// when it fires (no JS callback; the macrotask's `ClosureHandle` is an
    /// unused sentinel, dispatched before the closure path exactly like
    /// `pending_stream_emissions`).
    PromiseResolve {
        promise: crate::promise_model::PromiseHandle,
        value: crate::object_model::JsValue,
    },
}

/// Wrapper around f64 that provides Eq/Ord using total_cmp for determinism.
/// NaN values are equal to each other and greater than all other values.
/// -0.0 is less than +0.0 in the total ordering.
#[derive(Debug, Clone, Copy, Default)]
pub struct Float64(pub f64);

impl Float64 {
    /// Create a new Float64 from an f64.
    pub fn new(v: f64) -> Self {
        Self(v)
    }

    /// Check if this is NaN.
    pub fn is_nan(&self) -> bool {
        self.0.is_nan()
    }

    /// Check if this is positive or negative infinity.
    pub fn is_infinite(&self) -> bool {
        self.0.is_infinite()
    }

    /// Check if this is negative zero.
    pub fn is_negative_zero(&self) -> bool {
        self.0 == 0.0 && self.0.is_sign_negative()
    }

    /// Get the inner f64 value.
    pub fn inner(&self) -> f64 {
        self.0
    }
}

impl PartialEq for Float64 {
    fn eq(&self, other: &Self) -> bool {
        // Use total_cmp for bitwise equality (NaN == NaN, -0 != +0)
        self.0.total_cmp(&other.0) == Ordering::Equal
    }
}

impl Eq for Float64 {}

impl PartialOrd for Float64 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Float64 {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.total_cmp(&other.0)
    }
}

impl std::hash::Hash for Float64 {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.to_bits().hash(state);
    }
}

impl fmt::Display for Float64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_nan() {
            write!(f, "NaN")
        } else if self.0.is_infinite() {
            if self.0.is_sign_positive() {
                write!(f, "Infinity")
            } else {
                write!(f, "-Infinity")
            }
        } else if self.is_negative_zero() {
            write!(f, "0")
        } else {
            // ECMAScript Number::toString (shortest round-trip digits, exponent
            // form outside [1e-6, 1e21)); Rust's `{}` prints 2**70 as
            // 1180591620717411300000 and 1e-7 as 0.0000001 (bd-9vouw.2).
            f.write_str(ryu_js::Buffer::new().format(self.0))
        }
    }
}

impl Serialize for Float64 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Serialize as f64 bits for exact round-trip of NaN/special values
        serializer.serialize_u64(self.0.to_bits())
    }
}

impl<'de> Deserialize<'de> for Float64 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bits = u64::deserialize(deserializer)?;
        Ok(Self(f64::from_bits(bits)))
    }
}

impl From<f64> for Float64 {
    fn from(v: f64) -> Self {
        Self(v)
    }
}

impl From<i64> for Float64 {
    fn from(v: i64) -> Self {
        Self(v as f64)
    }
}

/// Minimum safe integer in JavaScript: -(2^53 - 1)
pub const MIN_SAFE_INTEGER: i64 = -9_007_199_254_740_991;
/// Maximum safe integer in JavaScript: 2^53 - 1
pub const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

/// Convert an f64 result to a JavaScript Number Value.
/// Preserves negative zero, handles NaN/Infinity, and represents whole numbers
/// within the safe integer range [-2^53+1, 2^53-1] as Value::Int.
#[inline(always)]
pub fn js_number_to_value(value: f64) -> Value {
    if value.is_nan() || value.is_infinite() {
        Value::Float(Float64::new(value))
    } else if value == 0.0 {
        if value.is_sign_negative() {
            Value::Float(Float64::new(-0.0))
        } else {
            Value::Int(0)
        }
    } else if value.fract() == 0.0
        && value >= MIN_SAFE_INTEGER as f64
        && value <= MAX_SAFE_INTEGER as f64
    {
        Value::Int(value as i64)
    } else {
        Value::Float(Float64::new(value))
    }
}

/// ES2020 6.1.6.1.3 Number::exponentiate. It differs from IEEE-754 `pow`
/// (`f64::powf`) in two cases: a NaN exponent gives NaN even for a base of 1,
/// and a base of +1 or -1 to an infinite exponent gives NaN, not 1.
#[inline]
pub fn js_exponentiate(base: f64, exponent: f64) -> f64 {
    if exponent.is_nan() || (base.abs() == 1.0 && exponent.is_infinite()) {
        f64::NAN
    } else {
        base.powf(exponent)
    }
}

/// `x + y` for two Numbers held as `Value::Int` (always safe integers), with
/// Number semantics: exact while the result is a safe integer, otherwise the
/// IEEE-754 double result (bd-9vouw.2). Never wraps.
#[inline(always)]
pub fn js_int_add(x: i64, y: i64) -> Value {
    match x.checked_add(y) {
        Some(sum) if (MIN_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&sum) => Value::Int(sum),
        _ => js_number_to_value(x as f64 + y as f64),
    }
}

/// `x - y` with Number semantics; see [`js_int_add`].
#[inline(always)]
pub fn js_int_sub(x: i64, y: i64) -> Value {
    match x.checked_sub(y) {
        Some(diff) if (MIN_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&diff) => Value::Int(diff),
        _ => js_number_to_value(x as f64 - y as f64),
    }
}

/// `x * y` with Number semantics, including `-0` for a zero product with a
/// negative factor; see [`js_int_add`].
#[inline(always)]
pub fn js_int_mul(x: i64, y: i64) -> Value {
    if (x == 0 && y < 0) || (y == 0 && x < 0) {
        return Value::Float(Float64::new(-0.0));
    }
    match x.checked_mul(y) {
        Some(prod) if (MIN_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&prod) => Value::Int(prod),
        _ => js_number_to_value(x as f64 * y as f64),
    }
}

/// `x % y` for Number operands held as integers, including a zero divisor,
/// a negative-zero remainder, and the overflowing `i64::MIN % -1` case.
/// Tier R and the compact numeric handler share this exact conversion.
#[inline(always)]
fn js_int_mod(x: i64, y: i64) -> Value {
    if y == 0 {
        return Value::Float(Float64::new(f64::NAN));
    }
    if let Some(rem) = x.checked_rem(y) {
        if x < 0 && rem == 0 {
            return Value::Float(Float64::new(-0.0));
        }
        return Value::Int(rem);
    }
    js_number_to_value(x as f64 % y as f64)
}

// ---------------------------------------------------------------------------
// Value — JS runtime value representation
// ---------------------------------------------------------------------------

/// Runtime value representation for the baseline interpreter.
///
/// This enum is intentionally non-exhaustive at the public crate boundary.
/// Downstream consumers must retain a fallback arm so additive JavaScript
/// value kinds can land without another source-breaking exhaustive-match
/// migration.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Value {
    /// Undefined.
    Undefined,
    /// Null.
    Null,
    /// Boolean.
    Bool(bool),
    /// Integer (i64). Fixed-point integers avoid floating-point
    /// non-determinism; fractional values use millionths when needed.
    Int(i64),
    /// BigInt primitive stored as canonical decimal digits without an `n`
    /// suffix. The string representation keeps serde deterministic without
    /// constraining literal size to the host integer width.
    BigInt(Arc<str>),
    /// IEEE 754 floating-point (f64). Used for fractional values, NaN,
    /// Infinity, and -0. Wrapped in Float64 for deterministic ordering.
    Float(Float64),
    /// Shared string payload. Cloning a `Value::Str` bumps refcounts instead
    /// of copying the string bytes on every register read/write. `JsString`
    /// carries exact UTF-16 code units when the content contains a lone
    /// surrogate (bd-neika) while keeping the UTF-8 fast path — and the
    /// previous wire format — for well-formed strings.
    Str(JsString),
    /// Object reference (heap index).
    Object(ObjectId),
    /// Function reference (function table index).
    Function(u32),
    /// Closure reference (index into interpreter closure store). Closures
    /// carry both a function_index and a captured scope chain snapshot.
    Closure(u32),
    /// Internal iterator state handle used by dedicated iteration instructions.
    Iterator(u32),
    /// Generator function reference (calling creates a suspended GeneratorObject).
    GeneratorFunction(u32),
    /// Live generator object reference (index into generator store).
    Generator(u32),
    /// Async function reference (calling creates a suspended AsyncFunctionObject).
    AsyncFunction(u32),
    /// Live async function object reference (index into async function store).
    AsyncFunctionObject(u32),
    /// Async generator function reference (calling creates a suspended AsyncGeneratorObject).
    AsyncGeneratorFunction(u32),
    /// Live async generator object reference (index into async generator store).
    AsyncGeneratorObject(u32),
    /// Promise handle (index into the promise store).
    Promise(u32),
    /// Builtin callable bound into the runtime environment.
    BuiltinFunction(BuiltinFunction),
    /// Internal accessor descriptor installed by class/object getter/setter definitions.
    Accessor {
        get: Option<Arc<Value>>,
        set: Option<Arc<Value>>,
    },
    /// ECMAScript Symbol primitive identity. This tail variant preserves all
    /// historical externally tagged serde discriminants.
    Symbol(SymbolId),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RuntimeSymbolKind {
    Private,
    Global,
    /// An ES2022 Private Name (`#x`) of one class evaluation. It keys
    /// [`HeapObject::private_elements`], never a property, and only the
    /// class's hidden `#x` binding holds it: guest code never sees it as a
    /// value.
    ClassPrivateName,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeSymbolRecord {
    symbol_id: SymbolId,
    kind: RuntimeSymbolKind,
    description: Option<JsString>,
    registry_key: Option<JsString>,
}

struct RuntimeSymbolRecordRef<'a>(&'a RuntimeSymbolRecord);

impl Serialize for RuntimeSymbolRecordRef<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct as _;

        let record = self.0;
        let mut wire = serializer.serialize_struct(
            "RuntimeSymbolRecord",
            if matches!(record.kind, RuntimeSymbolKind::Global) {
                4
            } else {
                3
            },
        )?;
        wire.serialize_field("symbol_id", &record.symbol_id.0)?;
        wire.serialize_field(
            "kind",
            match record.kind {
                RuntimeSymbolKind::Private => "private",
                RuntimeSymbolKind::Global => "global",
                RuntimeSymbolKind::ClassPrivateName => "class-private-name",
            },
        )?;
        wire.serialize_field("description", &record.description)?;
        if matches!(record.kind, RuntimeSymbolKind::Global) {
            wire.serialize_field("registry_key", &record.registry_key)?;
        }
        wire.end()
    }
}

/// Distinguishes a missing field from a present JSON `null` field.
#[derive(Debug)]
struct PresentNullable<T>(Option<T>);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for PresentNullable<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Option::<T>::deserialize(deserializer).map(Self)
    }
}

fn deserialize_present_nullable<'de, D, T>(
    deserializer: D,
) -> Result<Option<PresentNullable<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    PresentNullable::<T>::deserialize(deserializer).map(Some)
}

/// Distinguishes an absent optional field from a present non-null value.
#[derive(Debug)]
struct PresentValue<T>(T);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for PresentValue<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        T::deserialize(deserializer).map(Self)
    }
}

fn deserialize_present_value<'de, D, T>(
    deserializer: D,
) -> Result<Option<PresentValue<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    PresentValue::<T>::deserialize(deserializer).map(Some)
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct RuntimeSymbolState {
    next_symbol_id: u32,
    symbols: BTreeMap<SymbolId, RuntimeSymbolRecord>,
    // Derived lookup index, deliberately absent from the stable wire format.
    // Private Symbols and class-private names must not affect Symbol.for's
    // lookup cost. JsString preserves exact UTF-16 keys, including surrogates.
    global_symbols: BTreeMap<JsString, SymbolId>,
}

impl Default for RuntimeSymbolState {
    fn default() -> Self {
        Self {
            next_symbol_id: FIRST_DYNAMIC_SYMBOL_ID,
            symbols: BTreeMap::new(),
            global_symbols: BTreeMap::new(),
        }
    }
}

impl Serialize for RuntimeSymbolState {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct as _;

        let records = self
            .symbols
            .values()
            .map(RuntimeSymbolRecordRef)
            .collect::<Vec<_>>();
        let mut state = serializer.serialize_struct("RuntimeSymbolState", 3)?;
        state.serialize_field("well_known_schema", WELL_KNOWN_SYMBOL_SCHEMA)?;
        state.serialize_field("next_symbol_id", &self.next_symbol_id)?;
        state.serialize_field("symbols", &records)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for RuntimeSymbolState {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;

        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct SymbolStateWire {
            well_known_schema: String,
            next_symbol_id: u32,
            symbols: Vec<SymbolRecordWire>,
        }

        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct SymbolRecordWire {
            symbol_id: u32,
            kind: String,
            #[serde(default, deserialize_with = "deserialize_present_nullable")]
            description: Option<PresentNullable<JsString>>,
            #[serde(default, deserialize_with = "deserialize_present_nullable")]
            registry_key: Option<PresentNullable<JsString>>,
        }

        let wire = SymbolStateWire::deserialize(deserializer)?;
        if wire.well_known_schema != WELL_KNOWN_SYMBOL_SCHEMA {
            return Err(D::Error::custom("unknown well-known Symbol schema"));
        }
        let mut symbols = BTreeMap::new();
        let mut previous_id = None;
        for record in wire.symbols {
            let id = SymbolId(record.symbol_id);
            if let Some(previous) = previous_id
                && id <= previous
            {
                return Err(D::Error::custom(
                    "dynamic Symbol records must be strictly increasing",
                ));
            }
            previous_id = Some(id);
            let description = record
                .description
                .ok_or_else(|| D::Error::custom("Symbol description field is required"))?
                .0;
            let (kind, registry_key) = match record.kind.as_str() {
                kind @ ("private" | "class-private-name") => {
                    if record.registry_key.is_some() {
                        return Err(D::Error::custom(
                            "private Symbol record forbids registry_key",
                        ));
                    }
                    if kind == "private" {
                        (RuntimeSymbolKind::Private, None)
                    } else {
                        (RuntimeSymbolKind::ClassPrivateName, None)
                    }
                }
                "global" => {
                    let registry_key = record
                        .registry_key
                        .ok_or_else(|| {
                            D::Error::custom("global Symbol record requires registry_key")
                        })?
                        .0
                        .ok_or_else(|| {
                            D::Error::custom("global Symbol registry_key cannot be null")
                        })?;
                    if description.as_ref() != Some(&registry_key) {
                        return Err(D::Error::custom(
                            "global Symbol description must equal registry_key",
                        ));
                    }
                    (RuntimeSymbolKind::Global, Some(registry_key))
                }
                _ => return Err(D::Error::custom("unknown dynamic Symbol kind")),
            };
            if symbols
                .insert(
                    id,
                    RuntimeSymbolRecord {
                        symbol_id: id,
                        kind,
                        description,
                        registry_key,
                    },
                )
                .is_some()
            {
                return Err(D::Error::custom("duplicate dynamic Symbol id"));
            }
        }
        let mut state = Self {
            next_symbol_id: wire.next_symbol_id,
            symbols,
            global_symbols: BTreeMap::new(),
        };
        state.validate().map_err(D::Error::custom)?;
        // Validate before indexing: a hostile duplicate key must be rejected,
        // not silently replaced by BTreeMap::collect's last-writer behavior.
        state.global_symbols = state
            .symbols
            .values()
            .filter_map(|record| {
                record
                    .registry_key
                    .as_ref()
                    .map(|key| (key.clone(), record.symbol_id))
            })
            .collect();
        Ok(state)
    }
}

impl RuntimeSymbolState {
    pub(crate) fn is_default(&self) -> bool {
        self.next_symbol_id == FIRST_DYNAMIC_SYMBOL_ID && self.symbols.is_empty()
    }

    fn validate(&self) -> Result<(), String> {
        if self.next_symbol_id < FIRST_DYNAMIC_SYMBOL_ID {
            return Err("next_symbol_id overlaps reserved well-known Symbols".to_string());
        }
        let mut registry_keys = BTreeSet::new();
        for (id, record) in &self.symbols {
            if id.0 < FIRST_DYNAMIC_SYMBOL_ID || id.0 == u32::MAX {
                return Err(format!("invalid dynamic Symbol id {}", id.0));
            }
            if record.symbol_id != *id {
                return Err("dynamic Symbol record id mismatch".to_string());
            }
            if id.0 >= self.next_symbol_id {
                return Err(format!(
                    "dynamic Symbol id {} is not below next_symbol_id {}",
                    id.0, self.next_symbol_id
                ));
            }
            match record.kind {
                RuntimeSymbolKind::Private | RuntimeSymbolKind::ClassPrivateName => {
                    if record.registry_key.is_some() {
                        return Err("private Symbol has a registry key".to_string());
                    }
                }
                RuntimeSymbolKind::Global => {
                    let key = record
                        .registry_key
                        .as_ref()
                        .ok_or_else(|| "global Symbol lacks a registry key".to_string())?;
                    if record.description.as_ref() != Some(key) {
                        return Err("global Symbol description/registry mismatch".to_string());
                    }
                    if !registry_keys.insert(key.clone()) {
                        return Err("duplicate global Symbol registry key".to_string());
                    }
                }
            }
        }
        Ok(())
    }

    fn contains(&self, id: SymbolId) -> bool {
        (1..FIRST_DYNAMIC_SYMBOL_ID).contains(&id.0) || self.symbols.contains_key(&id)
    }

    fn is_class_private_name(&self, id: SymbolId) -> bool {
        self.symbols
            .get(&id)
            .is_some_and(|record| matches!(record.kind, RuntimeSymbolKind::ClassPrivateName))
    }

    fn global_symbol(&self, key: &JsString) -> Option<SymbolId> {
        self.global_symbols.get(key).copied()
    }

    fn allocate(
        &mut self,
        kind: RuntimeSymbolKind,
        description: Option<JsString>,
        registry_key: Option<JsString>,
    ) -> Result<SymbolId, InterpreterError> {
        if self.next_symbol_id == u32::MAX {
            return Err(InterpreterError::TypeError {
                expected: "available Symbol identity".to_string(),
                got: "Symbol identity space exhausted".to_string(),
            });
        }
        let symbol_id = SymbolId(self.next_symbol_id);
        self.next_symbol_id += 1;
        if let Some(key) = &registry_key {
            self.global_symbols.insert(key.clone(), symbol_id);
        }
        self.symbols.insert(
            symbol_id,
            RuntimeSymbolRecord {
                symbol_id,
                kind,
                description,
                registry_key,
            },
        );
        Ok(symbol_id)
    }

    fn key_for(&self, id: SymbolId) -> Option<&JsString> {
        self.symbols.get(&id).and_then(|record| {
            matches!(record.kind, RuntimeSymbolKind::Global)
                .then_some(record.registry_key.as_ref())
                .flatten()
        })
    }

    fn description(&self, id: SymbolId) -> Option<&JsString> {
        self.symbols
            .get(&id)
            .and_then(|record| record.description.as_ref())
    }
}

fn well_known_symbol_description(id: SymbolId) -> Option<&'static str> {
    match id.0 {
        1 => Some("Symbol.iterator"),
        2 => Some("Symbol.toPrimitive"),
        3 => Some("Symbol.hasInstance"),
        4 => Some("Symbol.toStringTag"),
        5 => Some("Symbol.species"),
        6 => Some("Symbol.isConcatSpreadable"),
        7 => Some("Symbol.unscopables"),
        8 => Some("Symbol.asyncIterator"),
        9 => Some("Symbol.match"),
        10 => Some("Symbol.matchAll"),
        11 => Some("Symbol.replace"),
        12 => Some("Symbol.search"),
        13 => Some("Symbol.split"),
        _ => None,
    }
}

/// Small set of builtin callable kinds the baseline interpreter exposes as
/// first-class values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuiltinFunctionKind {
    Require,
    FunctionConstructor,
    GeneratedFunction,
    IteratorNext,
    IteratorSelf,
    ConsoleLog,
    ConsoleError,
    ConsoleWarn,
    ConsoleInfo,
    StringCharAt,
    StringCharCodeAt,
    /// `String.prototype.at` - receiver-aware UTF-16 code-unit access with
    /// negative indices counting from the end (bd-s6t65).
    StringAt,
    /// `String.prototype.toUpperCase` — receiver-aware (bd-9a8cz).
    StringToUpperCase,
    /// `String.prototype.toLowerCase` — receiver-aware (bd-9a8cz).
    StringToLowerCase,
    /// `String.prototype.trim` — receiver-aware (bd-9a8cz).
    StringTrim,
    /// `String.prototype.split` — receiver-aware: returns an array of pieces;
    /// `undefined` separator → `[whole string]`, `""` → per-character (bd-9a8cz).
    StringSplit,
    /// `String.prototype.includes` — receiver-aware substring test (bd-9a8cz).
    StringIncludes,
    /// `String.prototype.startsWith` — receiver-aware prefix test (bd-9a8cz).
    StringStartsWith,
    /// `String.prototype.endsWith` — receiver-aware suffix test (bd-9a8cz).
    StringEndsWith,
    /// `String.prototype.indexOf` — receiver-aware; first index of the search
    /// string at/after an optional position, or -1 (bd-9a8cz.1).
    StringIndexOf,
    /// `String.prototype.lastIndexOf` — receiver-aware; highest start index of
    /// the search string at/before an optional position, or -1 (bd-9a8cz.1).
    StringLastIndexOf,
    /// `String.prototype.slice` — receiver-aware; negative indices count from
    /// the end (bd-9a8cz.1).
    StringSlice,
    /// `String.prototype.substring` — receiver-aware; clamps negatives to 0 and
    /// swaps start/end when start > end (bd-9a8cz.1).
    StringSubstring,
    /// `String.prototype.substr` — legacy (Annex B B.2.3.1) but normative;
    /// `substr(start, length)`: a negative start counts from the end
    /// (`max(len + start, 0)`) and an omitted length takes the rest. Distinct
    /// from `substring` (bd-fqlfw.2.11.2).
    StringSubstr,
    /// `String.prototype.replace` — receiver-aware; string search value,
    /// first-occurrence literal replacement (bd-9a8cz.1).
    StringReplace,
    /// `String.prototype.match` — receiver-aware; supports RegExp objects
    /// produced by literal/constructor lowering (bd-wni4m).
    StringMatch,
    /// `String.prototype.search` — receiver-aware; returns first match index
    /// or -1 for string or RegExp search values (bd-wni4m).
    StringSearch,
    /// `String.prototype.repeat` — receiver-aware; concatenates `count` copies
    /// (bd-9a8cz.1).
    StringRepeat,
    /// `String.prototype.padStart` — receiver-aware; left-pads to a target
    /// length (bd-9a8cz.1).
    StringPadStart,
    /// `String.prototype.padEnd` — receiver-aware; right-pads to a target
    /// length (bd-9a8cz.1).
    StringPadEnd,
    /// `String.prototype.trimStart` — receiver-aware; trims leading whitespace
    /// (ES2019) (bd-9hw6q).
    StringTrimStart,
    /// `String.prototype.trimEnd` — receiver-aware; trims trailing whitespace
    /// (ES2019) (bd-9hw6q).
    StringTrimEnd,
    /// `String.prototype.replaceAll` — receiver-aware; replaces every occurrence
    /// of a string search value (ES2021) (bd-9hw6q).
    StringReplaceAll,
    /// `String.prototype.codePointAt` — receiver-aware; the Unicode code point at
    /// a UTF-16 code-unit index (pairs combine, unpaired surrogates yield their
    /// own unit value), else `undefined` (ES2015) (bd-9hw6q, bd-rdnhc).
    StringCodePointAt,
    /// `String.prototype.localeCompare` — receiver-aware lexicographic compare
    /// using the existing simplified localeCompare builtin (bd-n9oxa).
    StringLocaleCompare,
    /// `String.prototype.normalize` — receiver-aware Unicode normalization using
    /// the existing normalize builtin (bd-n9oxa).
    StringNormalize,
    /// `Number.prototype.toFixed` — receiver-aware; fixed-point notation with a
    /// given number of digits after the decimal point (bd-i08nh).
    NumberToFixed,
    /// `Number.prototype.toString` — receiver-aware; supports an optional radix
    /// (2..=36), default 10 (bd-i08nh).
    NumberToString,
    /// `Number.prototype.valueOf` — receiver-aware; returns the primitive number
    /// value (bd-i08nh).
    NumberValueOf,
    /// `Boolean.prototype.toString` (ES2020 19.3.3.2): "true" or "false" for
    /// thisBooleanValue(this).
    BooleanPrototypeToString,
    /// `Boolean.prototype.valueOf` (ES2020 19.3.3.3): thisBooleanValue(this).
    BooleanPrototypeValueOf,
    ProxyRevoke,
    /// `Array.prototype.push` — receiver-aware: appends its arguments to the
    /// `this` array and returns the new length. Resolved on array exotic
    /// objects in `prototype_chain_get` (bd-bg9l1.27.9 / DISC-012).
    ArrayPush,
    /// `Array.prototype.pop` — receiver-aware: removes and returns the last
    /// element, decrementing `length`; returns `undefined` when empty
    /// (bd-962ev).
    ArrayPop,
    /// `Array.prototype.shift` — receiver-aware: removes and returns the first
    /// element, re-indexing the remainder down by one; `undefined` when empty
    /// (bd-962ev).
    ArrayShift,
    /// `Array.prototype.unshift` — receiver-aware: prepends its arguments,
    /// shifting existing elements up, and returns the new length (bd-962ev).
    ArrayUnshift,
    /// `Array.prototype.indexOf` — receiver-aware: first index strictly equal
    /// to the search element (from an optional `fromIndex`), else -1
    /// (bd-962ev.1).
    ArrayIndexOf,
    /// `Array.prototype.includes` — receiver-aware: SameValueZero membership
    /// test (NaN matches NaN), returning a boolean (bd-962ev.1).
    ArrayIncludes,
    /// `Array.prototype.reverse` — receiver-aware: reverses the elements in
    /// place and returns the array (bd-962ev.1).
    ArrayReverse,
    /// `Array.prototype.fill` — receiver-aware: fills `[start, end)` with a
    /// value in place (negative indices count from the end), returns the array
    /// (bd-962ev.1).
    ArrayFill,
    /// `Array.prototype.at` — receiver-aware: returns the element at `index`,
    /// where a negative index counts from the end; out-of-range => `undefined`
    /// (ES2022).
    ArrayAt,
    /// `Array.prototype.flat` — receiver-aware: returns a new array with
    /// sub-array elements concatenated into it recursively up to `depth`
    /// (default 1; `Infinity` flattens fully) (ES2019).
    ArrayFlat,
    /// `Array.prototype.join` — receiver-aware: concatenates elements with a
    /// separator (default `","`); `undefined`/`null` render as `""`
    /// (bd-962ev.1).
    ArrayJoin,
    /// `Array.prototype.toString` — receiver-aware: the spec join of the
    /// elements with `","` (ES2020 23.1.3.30), so arrays no longer fall back
    /// to `Object.prototype.toString`'s `[object Array]` tag (bd-sxh8o.3).
    ArrayToString,
    /// `Array.prototype.forEach` — receiver-aware: invokes the callback for each
    /// element, returns `undefined` (bd-962ev.2).
    ArrayForEach,
    /// `Array.prototype.map` — receiver-aware: returns a new array of callback
    /// results (bd-962ev.2).
    ArrayMap,
    /// `Array.prototype.filter` — receiver-aware: returns a new array of the
    /// elements for which the callback is truthy (bd-962ev.2).
    ArrayFilter,
    /// `Array.prototype.find` — receiver-aware: returns the first element for
    /// which the callback is truthy, else `undefined` (bd-962ev.2).
    ArrayFind,
    /// `Array.prototype.findIndex` — receiver-aware: returns the index of the
    /// first element for which the callback is truthy, else -1 (bd-962ev.2).
    ArrayFindIndex,
    /// `Array.prototype.findLast` — receiver-aware: the LAST element for which
    /// the callback is truthy (iterates in reverse), else `undefined` (ES2023)
    /// (bd-isqzc).
    ArrayFindLast,
    /// `Array.prototype.findLastIndex` — receiver-aware: index of the last
    /// element for which the callback is truthy (reverse), else -1 (ES2023)
    /// (bd-isqzc).
    ArrayFindLastIndex,
    /// `Array.prototype.flatMap` — receiver-aware: maps each element then
    /// flattens the result one level (ES2019) (bd-isqzc).
    ArrayFlatMap,
    /// `Array.prototype.copyWithin` — receiver-aware: copies the subsequence
    /// `[start, end)` to `target` in place; negative indices count from the end;
    /// returns the array (ES2015) (bd-xjkup).
    ArrayCopyWithin,
    /// `Array.prototype.some` — receiver-aware: true if the callback is truthy
    /// for any element (bd-962ev.2).
    ArraySome,
    /// `Array.prototype.every` — receiver-aware: true if the callback is truthy
    /// for every element (bd-962ev.2).
    ArrayEvery,
    /// `Array.prototype.reduce` — receiver-aware: left fold via the callback,
    /// with an optional initial value (bd-962ev.2).
    ArrayReduce,
    /// `Array.prototype.reduceRight` — receiver-aware: right fold via the
    /// callback, with an optional initial value (bd-962ev.2).
    ArrayReduceRight,
    /// `Array.prototype.sort` — receiver-aware: in-place sort, by an optional
    /// comparator (sign of its result) or lexicographically by default; returns
    /// the array (bd-962ev.2).
    ArraySort,
    /// `Array.prototype.concat` — receiver-aware: returns a new array of this
    /// array's elements followed by each argument (array arguments spread one
    /// level) (bd-962ev.1).
    ArrayConcat,
    /// `Array.prototype.slice` — receiver-aware: returns a new array for the
    /// `[start, end)` range (negative indices count from the end) (bd-962ev.1).
    ArraySliceMethod,
    /// `Array.prototype.lastIndexOf` — receiver-aware: last index strictly
    /// equal to the search element, scanning backward, else -1 (bd-962ev.1).
    ArrayLastIndexOf,
    /// `Array.prototype.splice` — receiver-aware: in-place remove `deleteCount`
    /// elements at `start` and insert the given items, returning an array of
    /// the removed elements (bd-962ev.1).
    ArraySplice,
    /// `Array.prototype.toReversed` (ES2023) — returns a reversed copy; the
    /// receiver is unchanged (bd-ib0ue).
    ArrayToReversed,
    /// `Array.prototype.toSorted` (ES2023) — returns a sorted copy using the
    /// same ordering as `sort` (optional comparator); receiver unchanged
    /// (bd-ib0ue).
    ArrayToSorted,
    /// `Array.prototype.with` (ES2023) — returns a copy with index `i` replaced
    /// by `value`; throws RangeError on out-of-range index (bd-ib0ue).
    ArrayWith,
    /// `Array.prototype.toSpliced` (ES2023) — returns a copy with `splice`
    /// applied; receiver unchanged (bd-ib0ue).
    ArrayToSpliced,
    /// `Array.prototype.entries` — receiver-aware runtime iterator over
    /// `[index, value]` pairs (bd-n9oxa).
    ArrayEntries,
    /// `Array.prototype.keys` — receiver-aware runtime iterator over indexes
    /// (bd-n9oxa).
    ArrayKeys,
    /// `Array.prototype.values` — receiver-aware runtime iterator over values
    /// (bd-n9oxa).
    ArrayValues,
    /// `Map.prototype.set(key, value)` — receiver-aware; inserts/overwrites and
    /// returns the Map for chaining (bd-juodx).
    MapSet,
    /// `Map.prototype.get(key)` — receiver-aware; value or `undefined` (bd-juodx).
    MapGet,
    /// `Map.prototype.has(key)` — receiver-aware boolean (bd-juodx).
    MapHas,
    /// `Map.prototype.delete(key)` — receiver-aware; removes and returns whether
    /// the key was present (bd-juodx).
    MapDelete,
    /// `Set.prototype.add(value)` — receiver-aware; inserts and returns the Set
    /// for chaining (bd-juodx).
    SetAdd,
    /// `Set.prototype.has(value)` — receiver-aware boolean (bd-juodx).
    SetHas,
    /// `Set.prototype.delete(value)` — receiver-aware; removes and returns
    /// whether the value was present (bd-juodx).
    SetDelete,
    /// `Map.prototype.clear()` — receiver-aware; empties the map, returns
    /// `undefined` (bd-juodx).
    MapClear,
    /// `Set.prototype.clear()` — receiver-aware; empties the set, returns
    /// `undefined` (bd-juodx).
    SetClear,
    /// `Date.prototype.getTime()` — receiver-aware; returns the Date object's
    /// private [[DateValue]] in milliseconds and throws a TypeError for a
    /// non-Date receiver (bd-cseei, bd-9vouw.150).
    DateGetTime,
    /// bd-3894s slice (2b): `ClientRequest.prototype.write(chunk)` — receiver-aware;
    /// appends `chunk` (string/number-coerced) to the request object's writable
    /// `__body` buffer and returns `true` (Node's writable-stream `write` returns a
    /// boolean backpressure signal). The egress is deferred until `.end()`.
    ClientRequestWrite,
    /// bd-3894s slice (2b): `ClientRequest.prototype.end([chunk])` — receiver-aware;
    /// appends an optional final `chunk` to `__body`, then performs the deferred
    /// `net:request` egress (method/headers captured at construction + the
    /// accumulated body) and returns the parsed response object. Idempotent: a
    /// second `.end()` is a no-op that returns `undefined`.
    ClientRequestEnd,
    /// bd-3894s slice (2d): `EventEmitter.prototype.on(event, listener)` shared by the
    /// HTTP `ClientRequest` (writable) and `IncomingMessage` (readable) stream objects.
    /// Registers `listener` for `event` in the interpreter's `event_listeners`
    /// side-table and returns the receiver for chaining (`res.on('data', …).on('end',
    /// …)`). Stream events are emitted on later event-loop turns: `'data'`/`'end'` on
    /// a response stream, `'response'`/`'error'` on a request.
    EmitterOn,
    /// `performance.now()` — deterministic virtual-clock read for replayable
    /// sandbox execution (bd-8enww.5.3).
    PerformanceNow,
    /// `DataView.prototype.getUint8(byteOffset)` over shared ArrayBuffer bytes
    /// (bd-8enww.2.6).
    DataViewGetUint8,
    /// `DataView.prototype.setUint8(byteOffset, value)` over shared ArrayBuffer
    /// bytes (bd-8enww.2.6).
    DataViewSetUint8,
    /// `DataView.prototype.getInt32(byteOffset, littleEndian?)` over shared
    /// ArrayBuffer bytes (bd-8enww.2.6).
    DataViewGetInt32,
    /// `DataView.prototype.setInt32(byteOffset, value, littleEndian?)` over
    /// shared ArrayBuffer bytes (bd-8enww.2.6).
    DataViewSetInt32,
    /// `DataView.prototype.getUint32(byteOffset, littleEndian?)` over shared
    /// ArrayBuffer bytes (bd-8enww.2.6).
    DataViewGetUint32,
    /// `DataView.prototype.setUint32(byteOffset, value, littleEndian?)` over
    /// shared ArrayBuffer bytes (bd-8enww.2.6).
    DataViewSetUint32,
    /// `TypedArray.prototype.set(source, offset?)` over shared ArrayBuffer bytes
    /// (bd-8enww.2.5).
    TypedArraySet,
    /// `TypedArray.prototype.subarray(begin?, end?)` returns a shared view
    /// (bd-8enww.2.5).
    TypedArraySubarray,
    /// `TypedArray.prototype.slice(begin?, end?)` returns a copied view
    /// (bd-8enww.2.5).
    TypedArraySlice,
    /// `TypedArray.prototype.fill(value, start?, end?)` over backing bytes
    /// (bd-8enww.2.5).
    TypedArrayFill,
    /// `TypedArray.prototype.copyWithin(target, start, end?)` over backing bytes
    /// (bd-8enww.2.5).
    TypedArrayCopyWithin,
    /// `TypedArray.prototype.entries()` iterator (bd-8enww.2.5).
    TypedArrayEntries,
    /// `TypedArray.prototype.keys()` iterator (bd-8enww.2.5).
    TypedArrayKeys,
    /// `TypedArray.prototype.values()` / `@@iterator` iterator (bd-8enww.2.5).
    TypedArrayValues,
    /// Deterministic diagnostic for common typed-array methods outside the v1
    /// BotGuard support surface (bd-8enww.2.5).
    TypedArrayUnsupportedMethod,
    /// `Promise.resolve(value)` — route the JS-visible static method to the
    /// internal promise model, yielding a real promise handle (bd-bpf76).
    PromiseResolve,
    /// `Promise.reject(reason)` — route to the internal promise model
    /// (bd-bpf76).
    PromiseReject,
    /// `Promise.all(iterable)` — route to the internal promise combinator
    /// (bd-bpf76).
    PromiseAll,
    /// `Promise.race(iterable)` — route to the internal promise combinator
    /// (bd-bpf76).
    PromiseRace,
    /// `Promise.allSettled(iterable)` — route to the internal promise
    /// combinator (bd-bpf76).
    PromiseAllSettled,
    /// `Promise.any(iterable)` — route to the internal promise combinator
    /// (bd-bpf76).
    PromiseAny,
    /// `Promise.prototype.then` — receiver-aware reaction registration
    /// (bd-bpf76).
    PromiseThen,
    /// `Promise.prototype.catch` — receiver-aware rejection reaction
    /// registration (bd-bpf76).
    PromiseCatch,
    /// `Promise.prototype.finally` — receiver-aware finally reaction
    /// registration (bd-bpf76).
    PromiseFinally,
    /// The executor NewPromiseCapability hands C (ES2020 25.6.1.5.1
    /// GetCapabilitiesExecutor), bound to a holder that records the resolve
    /// and reject C passes it (bd-9vouw.137, bd-9vouw.282).
    PromiseCapabilityExecutor,
    /// Promise.all Resolve Element Function (ES2020 25.6.4.1.2), bound to its
    /// element's holder (bd-9vouw.282).
    PromiseAllResolveElement,
    /// Promise.allSettled Resolve Element Function (ES2020 25.6.4.2.2).
    PromiseAllSettledResolveElement,
    /// Promise.allSettled Reject Element Function (ES2020 25.6.4.2.3).
    PromiseAllSettledRejectElement,
    /// Promise.any Reject Element Function (ES2021 27.2.4.3.2).
    PromiseAnyRejectElement,
    /// `RegExp.prototype.test` — receiver-aware; linear-time regex match via
    /// Rust's `regex` crate for the supported ES-compatible subset (bd-wni4m).
    RegExpTest,
    /// `Object.prototype.hasOwnProperty` — receiver-aware own-property test
    /// resolved through the object prototype fallback (bd-9a8cz.5).
    ObjectHasOwnProperty,
    /// `Object.prototype.propertyIsEnumerable` — receiver-aware own enumerable
    /// property test; heap data/accessor properties are enumerable today
    /// (bd-9a8cz.5).
    ObjectPrototypePropertyIsEnumerable,
    /// `Object.prototype.valueOf` — receiver-aware object/primitive identity
    /// result (bd-9a8cz.5).
    ObjectPrototypeValueOf,
    /// `Object.prototype.toString` — receiver-aware object tag string
    /// (bd-9a8cz.5).
    ObjectPrototypeToString,
    /// `String.prototype.isWellFormed` — true iff the receiver string
    /// contains no unpaired surrogate (ES2024 §22.1.3.10, bd-neika).
    /// Appended at the enum tail: `kind as u64` feeds the register hash, so
    /// existing ordinals must not shift.
    StringIsWellFormed,
    /// `String.prototype.toWellFormed` — each unpaired surrogate replaced
    /// with U+FFFD (ES2024 §22.1.3.29, bd-neika). Appended at the enum tail
    /// for the same ordinal-stability reason.
    StringToWellFormed,
    /// Global `setTimeout` as a first-class value (bd-suwvw). Injected into
    /// the realm global frame so bare references (`typeof setTimeout`,
    /// `require('timers').setTimeout === setTimeout`) resolve; calls dispatch
    /// to the same deterministic timer machinery as the lowering-recognized
    /// `builtin:SetTimeout` hostcall. Appended at the enum tail (ordinal
    /// stability).
    SetTimeout,
    /// Global `clearTimeout` as a first-class value (bd-suwvw).
    ClearTimeout,
    /// Global `setInterval` as a first-class value (bd-suwvw).
    SetInterval,
    /// Global `clearInterval` as a first-class value (bd-suwvw).
    ClearInterval,
    /// Global `setImmediate` as a first-class value (bd-suwvw).
    SetImmediate,
    /// Global `clearImmediate` as a first-class value (bd-suwvw).
    ClearImmediate,
    /// Global `queueMicrotask` as a first-class value (bd-suwvw).
    QueueMicrotask,
    /// `Timeout.prototype.hasRef` — bound to a specific timer-handle object
    /// via `bound_object` (bd-suwvw).
    TimerHasRef,
    /// `Timeout.prototype.ref` — bound timer-handle method (bd-suwvw).
    TimerRef,
    /// `Timeout.prototype.unref` — bound timer-handle method (bd-suwvw).
    TimerUnref,
    /// `fs.Stats.prototype.isFile()` (bd-8u1t5). Appended at the enum tail to
    /// preserve the register-hash ordinals of existing builtins.
    FsStatsIsFile,
    /// `fs.Stats.prototype.isDirectory()` (bd-8u1t5).
    FsStatsIsDirectory,
    /// `fs.Stats` / `fs.Dirent` `isSymbolicLink()` (bd-8u1t5).
    FsEntryIsSymbolicLink,
    /// `fs.Dirent.prototype.isFile()` (bd-8u1t5).
    FsDirentIsFile,
    /// `fs.Dirent.prototype.isDirectory()` (bd-8u1t5).
    FsDirentIsDirectory,
    /// `EventEmitter.prototype.once(event, listener)` (bd-2dmnn). EventEmitter
    /// variants are appended at the enum tail because the discriminant feeds
    /// deterministic register hashing.
    EmitterOnce,
    /// `EventEmitter.prototype.off/removeListener` (bd-2dmnn).
    EmitterOff,
    /// `EventEmitter.prototype.removeAllListeners` (bd-2dmnn).
    EmitterRemoveAllListeners,
    /// `EventEmitter.prototype.listenerCount` (bd-2dmnn).
    EmitterListenerCount,
    /// `EventEmitter.prototype.eventNames` (bd-2dmnn).
    EmitterEventNames,
    /// `EventEmitter.prototype.prependListener` (bd-2dmnn).
    EmitterPrependListener,
    /// `EventEmitter.prototype.prependOnceListener` (bd-2dmnn).
    EmitterPrependOnceListener,
    /// `EventEmitter.prototype.emit` (bd-2dmnn).
    EmitterEmit,
    /// `EventEmitter.prototype.getMaxListeners` (bd-2dmnn).
    EmitterGetMaxListeners,
    /// `EventEmitter.prototype.setMaxListeners` (bd-2dmnn).
    EmitterSetMaxListeners,
    /// `EventEmitter.prototype.listeners` (bd-2dmnn).
    EmitterListeners,
    /// `Buffer.prototype.toString(encoding?, start?, end?)` over Uint8Array
    /// backing bytes (bd-ys3f4). Buffer variants are appended at the true enum
    /// tail because the discriminant feeds deterministic register hashing.
    BufferToString,
    /// Node Buffer `slice`/`subarray`: a shared view retaining Buffer identity.
    BufferSharedSlice,
    /// `Buffer.prototype.indexOf` byte search.
    BufferIndexOf,
    /// `Buffer.prototype.includes` byte search predicate.
    BufferIncludes,
    /// `Buffer.prototype.equals` byte equality.
    BufferEquals,
    /// `Buffer.prototype.compare` lexicographic byte comparison.
    BufferCompare,
    /// Buffer unsigned 8-bit read/write methods.
    BufferReadUInt8,
    BufferWriteUInt8,
    /// Buffer unsigned 16-bit reads/writes.
    BufferReadUInt16Le,
    BufferReadUInt16Be,
    BufferWriteUInt16Le,
    BufferWriteUInt16Be,
    /// Buffer signed 32-bit reads/writes.
    BufferReadInt32Le,
    BufferReadInt32Be,
    BufferWriteInt32Le,
    BufferWriteInt32Be,
    /// Buffer unsigned 32-bit reads/writes.
    BufferReadUInt32Le,
    BufferReadUInt32Be,
    BufferWriteUInt32Le,
    BufferWriteUInt32Be,
    /// `Buffer.prototype.copy` between Uint8Array-backed byte views.
    BufferCopy,
    /// `Buffer.prototype.toJSON`.
    BufferToJson,
    /// In-place Buffer word-byte swaps.
    BufferSwap16,
    BufferSwap32,
    BufferSwap64,
    /// Node's other `Buffer.prototype` numeric accessors and `write`
    /// ([`BUFFER_NUMERIC_METHODS`], by method name in `module_specifier`;
    /// bd-9vouw.437).
    BufferNumericMethod,
    /// Receiver-independent `Array.isArray`, materialized by a dedicated pure
    /// factory hostcall for unshadowed static member reads (bd-cue2u).
    ArrayIsArray,
    /// `Readable.prototype.pause()` over the finite stream kernel (bd-fw7zd).
    /// Stream variants are appended at the true enum tail because the
    /// discriminant feeds deterministic register hashing.
    StreamReadablePause,
    /// `Readable.prototype.resume()`.
    StreamReadableResume,
    /// `Readable.prototype.isPaused()`.
    StreamReadableIsPaused,
    /// The deliberately narrow `Readable.prototype.push(null)` terminal path.
    StreamReadablePush,
    /// `Readable.from(...).toArray()` Promise consumption.
    StreamReadableToArray,
    /// `Readable.prototype.read()` over the engine-owned finite/custom queue.
    StreamReadableRead,
    /// UTF-8 decoding for subsequent custom-Readable Buffer pushes.
    StreamReadableSetEncoding,
    /// `Readable.prototype.destroy([error])` lifecycle teardown.
    StreamReadableDestroy,
    /// Identity coercion for `String.prototype.toString`. Writable's honest
    /// string-chunk representation exercises this ordinary primitive method.
    StringToString,
    /// `String.prototype.valueOf` (ES2020 21.1.3.30): thisStringValue(this).
    StringValueOf,
    /// `Writable.prototype.write()` over the engine-owned Writable kernel
    /// (bd-fw7zd). These variants remain at the true enum tail because the
    /// discriminant participates in deterministic register hashing.
    StreamWritableWrite,
    /// `Writable.prototype.end()`.
    StreamWritableEnd,
    /// Token-bound completion passed to a custom `_write` implementation.
    StreamWritableWriteDone,
    /// Token-bound completion passed to a custom `_final` implementation.
    StreamWritableFinalDone,
    /// `Writable.prototype.cork()` nesting over the engine-owned queue.
    StreamWritableCork,
    /// `Writable.prototype.uncork()` and zero-depth FIFO resumption.
    StreamWritableUncork,
    /// `Writable.prototype.destroy([error])` lifecycle teardown.
    StreamWritableDestroy,
    /// Hermetic same-interpreter `net.Server` / `net.Socket` methods
    /// (bd-7qwej). These variants remain at the true enum tail because the
    /// discriminant participates in deterministic register hashing.
    NetServerListen,
    NetServerAddress,
    NetServerClose,
    NetSocketWrite,
    NetSocketEnd,
    /// bd-m42c2: provider-backed `ChildProcess.kill` with Node signal
    /// vocabulary (default SIGTERM).
    ChildProcessKill,
    /// bd-m42c2: bounded `child.stdin.write(chunk)` through the lifecycle
    /// stdin writer.
    ChildProcessStdinWrite,
    /// bd-m42c2: `child.stdin.end()` closing the pipe (EOF to the child).
    ChildProcessStdinEnd,
    NetSocketDestroy,
    NetSocketSetEncoding,
    NetSocketPause,
    NetSocketResume,
    NetSocketRef,
    NetSocketUnref,
    NetSocketSetNoDelay,
    NetSocketSetKeepAlive,
    /// TLS-specific observations on a hermetic loopback socket (bd-70cv1).
    TlsSocketGetPeerCertificate,
    TlsSocketGetProtocol,
    TlsSocketGetCipher,
    TlsSocketIsSessionReused,
    TlsSocketGetSession,
    /// `Readable.prototype.unshift(chunk)` over the engine-owned queue
    /// (bd-fw7zd). Appended at the true enum tail because the discriminant
    /// participates in deterministic register hashing.
    StreamReadableUnshift,
    /// `Readable.prototype.pipe(destination)` for one engine-owned Writable
    /// destination (bd-7h43f). Pipe variants remain at the true enum tail
    /// because the discriminant participates in deterministic register
    /// hashing.
    StreamReadablePipe,
    /// Destination-bound listener that forwards one Readable `data` event
    /// through the existing Writable write kernel.
    StreamReadablePipeData,
    /// Destination-bound listener that forwards the Readable `end` event
    /// through the existing Writable terminal kernel.
    StreamReadablePipeEnd,
    /// `Readable.prototype.unpipe([destination])` for the authenticated
    /// single-destination pipe edge (bd-fw7zd.10).
    StreamReadableUnpipe,
    /// Engine-owned `_write`/`_final` callbacks coupling one PassThrough's
    /// Writable and Readable state without exposing a forgeable JS hook.
    StreamPassThroughWrite,
    StreamPassThroughFinal,
    /// Composite teardown for the two authenticated halves of PassThrough.
    StreamPassThroughDestroy,
    /// Transform-specific completion tokens. They remain at the enum tail
    /// because builtin discriminants participate in deterministic hashing.
    StreamTransformWriteDone,
    StreamTransformFinal,
    StreamTransformFinalDone,
    /// Authenticated terminal listeners owned by one `stream.pipeline` run.
    StreamPipelineFinish,
    StreamPipelineError,
    /// WHATWG `URLSearchParams` receiver methods. Appended at the true enum
    /// tail because builtin discriminants participate in deterministic hashes
    /// (bd-8y0gs).
    UrlSearchParamsGet,
    UrlSearchParamsHas,
    UrlSearchParamsGetAll,
    UrlSearchParamsAppend,
    UrlSearchParamsSort,
    UrlSearchParamsDelete,
    UrlSearchParamsSet,
    UrlSearchParamsToString,
    /// bd-9vouw.126: URLSearchParams.prototype.keys/values/entries (and
    /// @@iterator, which is entries): iterators over the pairs present at
    /// the call.
    UrlSearchParamsKeys,
    UrlSearchParamsValues,
    UrlSearchParamsEntries,
    /// URLSearchParams.prototype.forEach(callback, thisArg).
    UrlSearchParamsForEach,
    /// `cluster.setupPrimary` / legacy `setupMaster`: merge own enumerable
    /// option fields into the authenticated live settings object (bd-9p2v3).
    /// Cluster variants stay at the true enum tail because the discriminant
    /// participates in deterministic register hashing.
    ClusterSetup,
    /// Empty-primary `cluster.disconnect(callback)`: defer the callback onto
    /// the I/O completion lane without consulting host process state.
    ClusterDisconnect,
    /// Function-shaped `cluster.fork` and `cluster.Worker`; invocation always
    /// fails closed because the hermetic facade grants no process authority.
    ClusterFork,
    /// Function-shaped `cluster.Worker`, distinct from `fork` so callable
    /// identity and the observable function name are not forged.
    ClusterWorker,
    /// `Symbol.prototype.toString` bound to a primitive Symbol receiver.
    /// Kept at the true enum tail so existing deterministic discriminants stay
    /// stable when older replay payloads are decoded.
    SymbolPrototypeToString,
    /// `%StringIteratorPrototype%` factory exposed through the typed
    /// `Symbol.iterator` primitive lookup.
    StringIterator,
    /// Generator `Symbol.iterator` identity method.
    GeneratorIteratorSelf,
    /// Authenticated HTTP facade receiver methods (bd-d0n7u). Every HTTP
    /// variant is appended after the previous true tail because builtin
    /// discriminants participate in deterministic register hashing.
    HttpClientRequestWrite,
    HttpClientRequestEnd,
    HttpClientRequestSetHeader,
    HttpIncomingMessageSetEncoding,
    HttpIncomingMessageResume,
    HttpServerResponseSetHeader,
    HttpServerResponseGetHeader,
    HttpServerResponseHasHeader,
    HttpServerResponseRemoveHeader,
    HttpServerResponseWriteHead,
    HttpServerResponseWrite,
    HttpServerResponseEnd,
    /// Authenticated Node crypto receiver methods (bd-2z157). These remain at
    /// the true enum tail because builtin discriminants participate in the
    /// deterministic register hash.
    CryptoUpdate,
    CryptoDigest,
    CryptoCopy,
    CryptoCipherUpdate,
    CryptoCipherFinal,
    CryptoGetAuthTag,
    CryptoSetAuthTag,
    /// The writable global `Date` constructor (bd-1piai). Kept at the true
    /// enum tail because builtin discriminants participate in deterministic
    /// register hashes.
    DateConstructor,
    /// First-class `Date.now` method exposed by [`Self::DateConstructor`].
    DateNow,
    /// First-class methods on the writable global `Math` object (bd-1piai).
    /// These remain at the true enum tail for deterministic ordinal stability.
    MathAbs,
    MathCeil,
    MathFloor,
    MathRound,
    MathMax,
    MathMin,
    MathRandom,
    MathPow,
    MathSqrt,
    MathSin,
    MathCos,
    MathLog,
    MathExp,
    MathTan,
    MathTrunc,
    MathSign,
    MathAtan2,
    MathAsin,
    MathAcos,
    MathHypot,
    MathImul,
    MathAtan,
    MathLog10,
    MathLog2,
    MathCbrt,
    MathClz32,
    MathFround,
    MathAcosh,
    MathAsinh,
    MathAtanh,
    /// `EventEmitter.prototype.rawListeners(event)` (bd-asw4m.2). Appended at
    /// the true enum tail because builtin discriminants participate in
    /// deterministic register hashes.
    EmitterRawListeners,
    /// Stable callable wrapper created once per `once` registration. Its
    /// `bound_object` is the ordinary property carrier that exposes
    /// `.listener`; private invocation state remains interpreter-owned.
    EmitterOnceWrapper,
    /// First-class constructor reference for the finite Node EventEmitter
    /// surface (bd-dspwz). Appended at the true enum tail because builtin
    /// discriminants participate in deterministic register hashes.
    EventEmitterConstructor,
    /// First-class Function.prototype methods. Append only: existing builtin
    /// ordinals participate in deterministic register hashing.
    FunctionPrototypeCall,
    FunctionPrototypeApply,
    /// Receiver-branded synchronous generator methods. Append only: builtin
    /// discriminants participate in deterministic register hashing.
    GeneratorNext,
    GeneratorReturn,
    GeneratorThrow,
    /// Async methods have a separate receiver brand and always return Promises.
    AsyncGeneratorNext,
    AsyncGeneratorReturn,
    AsyncGeneratorThrow,
    AsyncGeneratorIteratorSelf,
    /// The writable global `Promise` constructor (bd-auy04). Its statics
    /// (`resolve`, `all`, ...) live on the bound property object, as for
    /// [`Self::DateConstructor`]. Append only: builtin discriminants
    /// participate in deterministic register hashing.
    PromiseConstructor,
    /// bd-9vouw.17: a standard ECMAScript constructor bound as a first-class
    /// global value (`Object`, `Array`, `Number`, `TypeError`, ...). The
    /// canonical constructor name travels in `module_specifier`, so two
    /// references are structurally equal (`TypeError === TypeError`). Append
    /// only: builtin discriminants participate in deterministic register
    /// hashing.
    StandardConstructor,
    /// bd-9vouw.17: a pure slot-0 static builtin read as a value
    /// (`const keys = Object.keys`, `JSON.stringify` through the `JSON`
    /// object). The `builtin:*` hostcall tag travels in `module_specifier` and
    /// is re-validated against the shared slot-0 table on every call.
    StaticHostcall,
    /// bd-9vouw.129: the getter of a built-in prototype accessor
    /// (`Map.prototype.size`, ...); `module_specifier` names it
    /// (`"Map.size"`, see `prototype_getters.rs`).
    PrototypeGetter,
    /// `Error.prototype.toString`, reached through the error prototypes'
    /// chain (bd-9vouw.17). Append only.
    ErrorPrototypeToString,
    /// `Function.prototype.bind` (ES2020 19.2.3.2). Append only.
    FunctionPrototypeBind,
    /// A bound function (ES2020 9.4.1) created by `bind`. Its `bound_object`
    /// is a private state object holding the target, the bound `this` and
    /// the bound arguments; it is never exposed as property storage.
    /// Append only.
    BoundFunction,
    /// `Map.prototype.forEach` / `Set.prototype.forEach` (bd-9vouw.33).
    /// Append only.
    MapForEach,
    SetForEach,
    /// `Map.prototype.keys/values/entries`, `Set.prototype.values/entries`
    /// (bd-9vouw.33). Append only.
    MapKeys,
    MapValues,
    MapEntries,
    SetValues,
    SetEntries,
    /// `String.prototype.concat`. Append only.
    StringPrototypeConcat,
    /// `Number.prototype.toPrecision` / `toExponential`. Append only.
    NumberToPrecision,
    NumberToExponential,
    /// A `Date.prototype` getter/setter/formatter; the method name travels in
    /// `module_specifier` (one of [`DATE_PROTOTYPE_METHODS`]). Append only.
    DatePrototypeMethod,
    /// `RegExp.prototype.exec` (ES2020 21.2.5.2). Append only.
    RegExpPrototypeExec,
    /// `WeakMap.prototype.get/set/has/delete`; the method name travels in
    /// `module_specifier`. Append only.
    WeakMapMethod,
    /// `Date.UTC` / `Date.parse` (ES2020 20.4.3). Append only.
    DateUtc,
    DateParse,
    /// `Promise.prototype.finally` reaction steps (ES2020 25.6.5.3.1-2),
    /// bound (via `bound_object`) to a holder whose `__onFinally` is the user
    /// callback: call it with no arguments, then pass the original value
    /// (`PromiseThenFinally`) or rethrow the original reason
    /// (`PromiseCatchFinally`) once its result settles (bd-9vouw.39). Append
    /// only.
    PromiseThenFinally,
    PromiseCatchFinally,
    /// Continuations after `onFinally` returned a Promise: return, or throw,
    /// the `__value` of the bound holder (bd-9vouw.39). Append only.
    PromiseFinallyValueThunk,
    PromiseFinallyThrower,
    /// `Object.prototype.isPrototypeOf` (ES2020 19.1.3.3). Append only.
    ObjectPrototypeIsPrototypeOf,
    /// `BigInt.prototype.toString` / `valueOf` / `toLocaleString` and
    /// `BigInt.asUintN` / `asIntN` (ES2020 20.2). Append only.
    BigIntToString,
    BigIntValueOf,
    BigIntAsUintN,
    BigIntAsIntN,
    /// `WeakSet.prototype.add/has/delete`; the method name travels in
    /// `module_specifier`. Append only.
    WeakSetMethod,
    /// TextEncoder.prototype.encode/encodeInto, TextDecoder.prototype.decode
    /// (bd-3l74k); the method name is in `module_specifier`.
    TextCodecMethod,
    /// `next` / `return` of the async iterator that
    /// `require('timers/promises').setInterval` returns (bd-suwvw). Append
    /// only.
    TimersPromisesIntervalNext,
    TimersPromisesIntervalReturn,
    /// `Function.prototype.toString` (ES2020 19.2.3.5). Append only.
    FunctionPrototypeToString,
    /// `DataView.prototype` accessors beyond getUint8/getInt32/getUint32 and
    /// their setters (Int8, Int16, Uint16, Float32, Float64, BigInt64,
    /// BigUint64); the method name travels in `module_specifier` (one of
    /// [`DATA_VIEW_METHODS`]). Append only.
    DataViewMethod,
    /// `RegExp.prototype.toString` (ES2020 21.2.5.14). Append only.
    RegExpPrototypeToString,
    /// `%TypedArray%.prototype` map / filter / reverse / sort (ES2020
    /// 22.2.3); the method name travels in `module_specifier` (one of
    /// [`TYPED_ARRAY_METHODS`]). Append only.
    TypedArrayMethod,
    /// `String.prototype.matchAll` (ES2020 21.1.3.12). Append only.
    StringMatchAll,
    /// V8's `Error.captureStackTrace(target[, constructorOpt])`, which npm
    /// error classes call unguarded. Append only.
    ErrorCaptureStackTrace,
    /// `ArrayBuffer.prototype.slice` (ES2020 24.1.4.3). Append only.
    ArrayBufferSlice,
    /// `WeakRef.prototype.deref` (ES2021 26.1.3.2). Append only.
    WeakRefDeref,
    /// `FinalizationRegistry.prototype.register` / `unregister` (ES2021
    /// 26.2.3); the method name travels in `module_specifier`. Append only.
    FinalizationRegistryMethod,
    /// `RegExp.prototype[@@match]`, `[@@matchAll]`, `[@@replace]`,
    /// `[@@search]` and `[@@split]` (ES2020 21.2.5); the `@@name` travels in
    /// `module_specifier`. Append only.
    RegExpSymbolMethod,
    /// `%TypedArray%.from` / `%TypedArray%.of` (ES2020 22.2.2.1-2), reached
    /// as `Uint8Array.from`; the method name travels in `module_specifier`
    /// and the element type comes from the `this` constructor. Append only.
    TypedArrayStaticMethod,
    /// `Number.prototype.toLocaleString` (ECMA-402 subset, see
    /// number_locale.rs). Append only.
    NumberToLocaleString,
    /// `Intl.NumberFormat`, `Intl.DateTimeFormat`, `Intl.Collator` and
    /// `Intl.PluralRules` (ECMA-402, intl.rs); the service name travels in
    /// `module_specifier`. Append only.
    IntlConstructor,
    /// A service object's `format`, `compare`, `select` or
    /// `resolvedOptions`, bound to it (`bound_object`); `module_specifier`
    /// holds `<service>.<method>`. Append only.
    IntlMethod,
    /// `Intl.getCanonicalLocales` (ECMA-402 8.3.1). Append only.
    IntlGetCanonicalLocales,
    /// `Object.prototype.toLocaleString` (ES2020 19.1.3.5). Append only.
    ObjectPrototypeToLocaleString,
    /// `Array.prototype.toLocaleString` (ES2020 22.1.3.27); with the
    /// %TypedArray%.prototype specifier, the typed array one (22.2.3.28).
    /// Append only.
    ArrayToLocaleString,
    /// Math.sinh, cosh, tanh, expm1 and log1p (ES2020 20.2.2.31, .13, .34,
    /// .15, .21): absent, so `Math.tanh(1)` was a TypeError (calling
    /// undefined). Append only.
    MathSinh,
    MathCosh,
    MathTanh,
    MathExpm1,
    MathLog1p,
    /// A Proxy whose target is callable (ES2020 9.5.12, 9.5.13): the value
    /// guest code holds for `new Proxy(fn, handler)`. `bound_object` is the
    /// proxy record (target, handler, revoked flag and the callable target),
    /// so [[Get]]/[[Set]]/... reach its traps like an object proxy's, while
    /// [[Call]] and [[Construct]] go through `apply` / `construct` (or the
    /// target). Append only.
    CallableProxy,
    /// The other `console` methods (bd-9vouw.158): `debug`, `assert`,
    /// `count`, `group`, `time`, ... named by the specifier, one of
    /// [`CONSOLE_EXTRA_METHODS`]. Append only.
    ConsoleMethod,
    /// `URL.prototype.toString` and `toJSON` (bd-9vouw.157), named by the
    /// specifier: the receiver URL's href. Append only.
    UrlMethod,
    /// ES2024 `Promise.withResolvers()`: `{ promise, resolve, reject }`
    /// for a new promise of `this` (bd-9vouw.160). Append only.
    PromiseWithResolvers,
    /// ES2025 `Set.prototype.union`, `intersection`, `difference`,
    /// `symmetricDifference`, `isSubsetOf`, `isSupersetOf` and
    /// `isDisjointFrom` (set_algebra.rs), named by the specifier. Append only.
    SetMethod,
    /// `URL.canParse` and `URL.parse` (URL Standard 6.1), named by the
    /// specifier. Append only.
    UrlStatic,
    /// Annex B `Object.prototype.__defineGetter__`, `__defineSetter__`,
    /// `__lookupGetter__` and `__lookupSetter__` (bd-9vouw.172), named by
    /// the specifier. Append only.
    ObjectLegacyAccessor,
    /// `Array.fromAsync` resumption steps (ES2024 23.1.2.1, bd-9vouw.172),
    /// registered as reactions on each awaited promise and bound (via
    /// `bound_object`) to the holder that carries the call's state: the
    /// fulfilled step continues with the awaited value, the rejected step
    /// with the awaited reason. Append only.
    ArrayFromAsyncFulfilled,
    ArrayFromAsyncRejected,
    /// The methods of `EventTarget`, `Event`, `AbortController` and
    /// `AbortSignal` and the `AbortSignal` statics (bd-9vouw.170), named by
    /// the specifier, one of [`event_target::EVENT_TARGET_METHODS`]. Append
    /// only.
    EventTargetMethod,
    /// ES2025 Iterator helpers (bd-9vouw.179): `Iterator.from`, the
    /// %IteratorPrototype% methods and the `next` / `return` of
    /// %IteratorHelperPrototype% and %WrapForValidIteratorPrototype%, named
    /// by the specifier, one of [`iterator_helpers::ITERATOR_HELPER_METHODS`].
    /// Append only.
    IteratorHelperMethod,
    /// Annex B `String.prototype.anchor`, `big`, `blink`, `bold`, `fixed`,
    /// `fontcolor`, `fontsize`, `italics`, `link`, `small`, `strike`, `sub`
    /// and `sup` (bd-9vouw.185), named by the specifier, one of
    /// [`STRING_HTML_METHODS`]. Append only.
    StringHtmlMethod,
    /// `require.resolve` of the module named by the specifier (bd-9vouw.199).
    /// Append only.
    RequireResolve,
    /// `Symbol.prototype.valueOf` (ES2020 19.4.3.4): thisSymbolValue, so a
    /// Symbol wrapper object answers its symbol (bd-9vouw.234). Append only.
    SymbolPrototypeValueOf,
    /// Blob.prototype.slice / text / arrayBuffer (bd-9vouw.226), named by
    /// the specifier, one of [`blob::BLOB_METHODS`]. Append only.
    BlobMethod,
    /// `Symbol.prototype[@@toPrimitive]` (ES2020 19.4.3.5): thisSymbolValue
    /// whatever the hint, so ToPrimitive of a Symbol wrapper is its symbol
    /// (bd-9vouw.239). Append only.
    SymbolPrototypeToPrimitive,
    /// Annex B `RegExp.prototype.compile(pattern, flags)` (ES2020
    /// B.2.5.1): RegExpInitialize of the receiver in place
    /// (bd-9vouw.241). Append only.
    RegExpPrototypeCompile,
    /// `SharedArrayBuffer.prototype.slice` / `grow` (ES2020 24.2.4,
    /// bd-9vouw.244), named by the specifier. Append only.
    SharedArrayBufferMethod,
    /// An `Atomics` namespace method (ES2020 24.4, bd-9vouw.245), named by
    /// the specifier, one of [`atomics::ATOMICS_METHODS`]. Append only.
    AtomicsMethod,
    /// `ArrayBuffer.prototype.resize` / `transfer` / `transferToFixedLength`
    /// (ES2024 25.1.6, bd-9vouw.256), named by the specifier, one of
    /// [`resizable_buffers::ARRAY_BUFFER_METHODS`]. Append only.
    ArrayBufferMethod,
    /// `Date.prototype[@@toPrimitive](hint)` (ES2020 20.3.4.45):
    /// OrdinaryToPrimitive with "default" read as "string"
    /// (bd-9vouw.259). Append only.
    DatePrototypeToPrimitive,
    /// `Function.prototype[@@hasInstance](V)` (ES2020 19.2.3.6):
    /// OrdinaryHasInstance(this, V) (bd-9vouw.268). Append only.
    FunctionPrototypeHasInstance,
    /// %ThrowTypeError% (ES2020 9.2.9.1): throws a TypeError. The `get` and
    /// `set` of every arguments object's `callee` but a sloppy function
    /// with a simple parameter list's (bd-9vouw.272). Append only.
    ThrowTypeError,
    /// `set Object.prototype.__proto__` (Annex B.2.2.1.2), the setter of the
    /// accessor whose getter is the `"Object.__proto__"` PrototypeGetter
    /// (bd-9vouw.284). Append only.
    ObjectProtoSetter,
    /// %Function.prototype% (ES2020 19.2.3): a callable, non-constructible
    /// function that returns undefined. Its bound object is the realm's
    /// canonical Function prototype property storage (bd-9vouw.346).
    FunctionPrototype,
    /// The timers.promises getter reads the exports of its private native
    /// factory carrier. It never calls guest code; the bound holder retains
    /// both the returned reference label and the collector edge. Append only.
    NativeTimerPromisesGetter,
    /// `node:module.createRequire` for the executing captured origin. The
    /// returned require retains the opaque module id. Append only.
    ModuleCreateRequire,
    /// First-class HTTP module exports retain their exact hostcall identity.
    /// Node exposes ordinary constructible functions here. Append only:
    /// builtin ordinals participate in deterministic register hashing.
    NativeHttpFunction,
    /// First-class child_process exports retain the authenticated operation;
    /// invocation still crosses the process_spawn policy and journal seam.
    /// Append only: builtin ordinals are part of register hashing.
    NativeChildProcessFunction,
    /// The defining module's synchronous URL metadata resolver. Append only:
    /// builtin ordinals participate in deterministic register hashing.
    ImportMetaResolve,
}

/// Annex B B.2.2.2-14: each String HTML method's tag and attribute name.
const STRING_HTML_METHODS: [(&str, &str, Option<&str>); 13] = [
    ("anchor", "a", Some("name")),
    ("big", "big", None),
    ("blink", "blink", None),
    ("bold", "b", None),
    ("fixed", "tt", None),
    ("fontcolor", "font", Some("color")),
    ("fontsize", "font", Some("size")),
    ("italics", "i", None),
    ("link", "a", Some("href")),
    ("small", "small", None),
    ("strike", "strike", None),
    ("sub", "sub", None),
    ("sup", "sup", None),
];

impl BuiltinFunctionKind {
    /// Whether this first-class builtin implements ECMAScript `[[Construct]]`.
    ///
    /// Most builtins exposed by this interpreter are callable methods. The
    /// `Function`, the materialized writable `Date` and `Promise` globals, and
    /// the authenticated EventEmitter reference are constructible builtin
    /// values; other globals lower to dedicated hostcalls instead of passing
    /// through [`Value::BuiltinFunction`] (bd-zyndq, bd-1piai, bd-auy04).
    const fn is_constructible(self) -> bool {
        matches!(
            self,
            Self::FunctionConstructor
                | Self::GeneratedFunction
                | Self::DateConstructor
                | Self::EventEmitterConstructor
                | Self::PromiseConstructor
                | Self::StandardConstructor
                | Self::IntlConstructor
                | Self::NativeHttpFunction
                | Self::NativeChildProcessFunction
                // Whether a callable proxy constructs depends on its target;
                // `construct_callable_proxy` checks that.
                | Self::CallableProxy
        )
    }

    /// Native factories whose callee selection contributes to an immediate
    /// host effect, including indirect calls and constructor invocations.
    const fn observes_host_effect_selection(self) -> bool {
        matches!(
            self,
            Self::NativeHttpFunction | Self::NativeChildProcessFunction
        )
    }
}

/// First-class builtin callable value with the module provenance needed for
/// deterministic CommonJS resolution.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct BuiltinModuleSpecifier(Option<Arc<str>>);

impl BuiltinModuleSpecifier {
    fn from_nonempty(value: &str) -> Self {
        if value.is_empty() {
            Self::default()
        } else {
            Self(Some(Arc::from(value)))
        }
    }
}

impl std::ops::Deref for BuiltinModuleSpecifier {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0.as_deref().unwrap_or_default()
    }
}

impl AsRef<str> for BuiltinModuleSpecifier {
    fn as_ref(&self) -> &str {
        self
    }
}

impl From<&str> for BuiltinModuleSpecifier {
    fn from(value: &str) -> Self {
        Self::from_nonempty(value)
    }
}

impl From<String> for BuiltinModuleSpecifier {
    fn from(value: String) -> Self {
        Self::from_nonempty(&value)
    }
}

impl From<Arc<str>> for BuiltinModuleSpecifier {
    fn from(value: Arc<str>) -> Self {
        if value.is_empty() {
            Self::default()
        } else {
            Self(Some(value))
        }
    }
}

impl Serialize for BuiltinModuleSpecifier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self)
    }
}

impl<'de> Deserialize<'de> for BuiltinModuleSpecifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Ok(Self::from_nonempty(&value))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BuiltinFunction {
    pub kind: BuiltinFunctionKind,
    #[serde(default, skip_serializing_if = "builtin_module_specifier_is_empty")]
    pub module_specifier: BuiltinModuleSpecifier,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iterator_handle: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_object: Option<u32>,
}

fn builtin_module_specifier_is_empty(value: &BuiltinModuleSpecifier) -> bool {
    value.is_empty()
}

impl BuiltinFunction {
    fn new_kind(kind: BuiltinFunctionKind) -> Self {
        Self {
            kind,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    /// A builtin closure over engine-owned state kept in `holder`'s
    /// properties (Promise.prototype.finally steps, bd-9vouw.39).
    fn bound_to(kind: BuiltinFunctionKind, holder: ObjectId) -> Self {
        Self {
            kind,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: Some(holder.0),
        }
    }

    fn symbol_to_string() -> Self {
        Self::new_kind(BuiltinFunctionKind::SymbolPrototypeToString)
    }

    /// bd-9vouw.17: first-class standard constructor value (`TypeError`, ...).
    fn standard_constructor(name: &'static str) -> Self {
        Self {
            kind: BuiltinFunctionKind::StandardConstructor,
            module_specifier: BuiltinModuleSpecifier::from_nonempty(name),
            iterator_handle: None,
            bound_object: None,
        }
    }

    /// bd-9vouw.17: first-class pure static builtin (`Object.keys`, ...).
    fn static_hostcall(tag: &'static str) -> Self {
        Self {
            kind: BuiltinFunctionKind::StaticHostcall,
            module_specifier: BuiltinModuleSpecifier::from_nonempty(tag),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn native_http_function(tag: &'static str) -> Self {
        Self {
            kind: BuiltinFunctionKind::NativeHttpFunction,
            module_specifier: BuiltinModuleSpecifier::from_nonempty(tag),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn native_child_process_function(operation: &'static str) -> Self {
        Self {
            kind: BuiltinFunctionKind::NativeChildProcessFunction,
            module_specifier: BuiltinModuleSpecifier::from_nonempty(operation),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn string_iterator() -> Self {
        Self::new_kind(BuiltinFunctionKind::StringIterator)
    }

    fn generator_iterator_self() -> Self {
        Self::new_kind(BuiltinFunctionKind::GeneratorIteratorSelf)
    }

    /// `require.resolve` of the module a `require` belongs to (bd-9vouw.199).
    fn require_resolve(require: &BuiltinFunction) -> Self {
        Self {
            kind: BuiltinFunctionKind::RequireResolve,
            module_specifier: require.module_specifier.clone(),
            iterator_handle: None,
            bound_object: require.bound_object,
        }
    }

    fn import_meta_resolve(module_specifier: &str) -> Self {
        Self {
            kind: BuiltinFunctionKind::ImportMetaResolve,
            module_specifier: BuiltinModuleSpecifier::from_nonempty(module_specifier),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn require(module_specifier: impl AsRef<str>) -> Self {
        let module_specifier = module_specifier.as_ref();
        Self {
            kind: BuiltinFunctionKind::Require,
            module_specifier: BuiltinModuleSpecifier::from_nonempty(module_specifier),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn function_constructor() -> Self {
        Self::new_kind(BuiltinFunctionKind::FunctionConstructor)
    }

    fn date_constructor(property_object: ObjectId) -> Self {
        Self {
            kind: BuiltinFunctionKind::DateConstructor,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: Some(property_object.0),
        }
    }

    fn promise_constructor(property_object: ObjectId) -> Self {
        Self {
            kind: BuiltinFunctionKind::PromiseConstructor,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: Some(property_object.0),
        }
    }

    fn generated_function(owner_program_id: ContentHash, artifact_id: ContentHash) -> Self {
        Self {
            kind: BuiltinFunctionKind::GeneratedFunction,
            module_specifier: BuiltinModuleSpecifier::from_nonempty(&format!(
                "genfn:v1:{}:{}",
                owner_program_id.to_hex(),
                artifact_id.to_hex()
            )),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn iterator_next(iterator_handle: u32) -> Self {
        Self {
            kind: BuiltinFunctionKind::IteratorNext,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: Some(iterator_handle),
            bound_object: None,
        }
    }

    fn iterator_self(iterator_handle: u32) -> Self {
        Self {
            kind: BuiltinFunctionKind::IteratorSelf,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: Some(iterator_handle),
            bound_object: None,
        }
    }

    fn string_char_at() -> Self {
        Self {
            kind: BuiltinFunctionKind::StringCharAt,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn string_is_well_formed() -> Self {
        Self {
            kind: BuiltinFunctionKind::StringIsWellFormed,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn string_to_well_formed() -> Self {
        Self {
            kind: BuiltinFunctionKind::StringToWellFormed,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    /// bd-suwvw: a global timer builtin as a first-class value. Structural
    /// equality on `BuiltinFunction` makes every reference to the same global
    /// (`setTimeout`, `require('timers').setTimeout`) compare `===` equal.
    fn timer_global(kind: BuiltinFunctionKind) -> Self {
        Self::new_kind(kind)
    }

    /// bd-suwvw: a `hasRef`/`ref`/`unref` method bound to one timer-handle
    /// object (mirrors `proxy_revoke`'s `bound_object` pattern).
    fn timer_handle_method(kind: BuiltinFunctionKind, handle_object: ObjectId) -> Self {
        Self {
            kind,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: Some(handle_object.0),
        }
    }

    fn writable_completion(kind: BuiltinFunctionKind, object_id: ObjectId, token: u32) -> Self {
        Self {
            kind,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: Some(token),
            bound_object: Some(object_id.0),
        }
    }

    fn readable_pipe_listener(
        kind: BuiltinFunctionKind,
        destination: ObjectId,
        token: u32,
    ) -> Self {
        debug_assert!(matches!(
            kind,
            BuiltinFunctionKind::StreamReadablePipeData
                | BuiltinFunctionKind::StreamReadablePipeEnd
        ));
        Self {
            kind,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: Some(token),
            bound_object: Some(destination.0),
        }
    }

    fn stream_pipeline_listener(kind: BuiltinFunctionKind, token: u32, stage: ObjectId) -> Self {
        debug_assert!(matches!(
            kind,
            BuiltinFunctionKind::StreamPipelineFinish | BuiltinFunctionKind::StreamPipelineError
        ));
        Self {
            kind,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: Some(token),
            bound_object: Some(stage.0),
        }
    }

    fn emitter_once_wrapper(property_object: ObjectId) -> Self {
        Self {
            kind: BuiltinFunctionKind::EmitterOnceWrapper,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: Some(property_object.0),
        }
    }

    fn string_char_code_at() -> Self {
        Self {
            kind: BuiltinFunctionKind::StringCharCodeAt,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn string_at() -> Self {
        Self {
            kind: BuiltinFunctionKind::StringAt,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn string_to_upper_case() -> Self {
        Self {
            kind: BuiltinFunctionKind::StringToUpperCase,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn string_to_lower_case() -> Self {
        Self {
            kind: BuiltinFunctionKind::StringToLowerCase,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    /// `String.prototype.toLocaleUpperCase` / `toLocaleLowerCase`: the case
    /// mappings under the root locale, but their own function objects named
    /// for themselves (bd-9vouw.383); the specifier names the member.
    fn string_to_locale_case(kind: BuiltinFunctionKind, name: &str) -> Self {
        Self {
            kind,
            module_specifier: BuiltinModuleSpecifier::from_nonempty(name),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn string_trim() -> Self {
        Self {
            kind: BuiltinFunctionKind::StringTrim,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn string_split() -> Self {
        Self {
            kind: BuiltinFunctionKind::StringSplit,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn string_includes() -> Self {
        Self {
            kind: BuiltinFunctionKind::StringIncludes,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn string_starts_with() -> Self {
        Self {
            kind: BuiltinFunctionKind::StringStartsWith,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn string_ends_with() -> Self {
        Self {
            kind: BuiltinFunctionKind::StringEndsWith,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn string_index_of() -> Self {
        Self {
            kind: BuiltinFunctionKind::StringIndexOf,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn string_last_index_of() -> Self {
        Self {
            kind: BuiltinFunctionKind::StringLastIndexOf,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn string_slice() -> Self {
        Self {
            kind: BuiltinFunctionKind::StringSlice,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn string_substring() -> Self {
        Self {
            kind: BuiltinFunctionKind::StringSubstring,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn string_substr() -> Self {
        Self {
            kind: BuiltinFunctionKind::StringSubstr,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn string_replace() -> Self {
        Self {
            kind: BuiltinFunctionKind::StringReplace,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn string_match() -> Self {
        Self {
            kind: BuiltinFunctionKind::StringMatch,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn string_search() -> Self {
        Self {
            kind: BuiltinFunctionKind::StringSearch,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn string_repeat() -> Self {
        Self {
            kind: BuiltinFunctionKind::StringRepeat,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn string_trim_start() -> Self {
        Self {
            kind: BuiltinFunctionKind::StringTrimStart,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn string_trim_end() -> Self {
        Self {
            kind: BuiltinFunctionKind::StringTrimEnd,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn string_replace_all() -> Self {
        Self {
            kind: BuiltinFunctionKind::StringReplaceAll,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn string_code_point_at() -> Self {
        Self {
            kind: BuiltinFunctionKind::StringCodePointAt,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn string_locale_compare() -> Self {
        Self {
            kind: BuiltinFunctionKind::StringLocaleCompare,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn string_normalize() -> Self {
        Self {
            kind: BuiltinFunctionKind::StringNormalize,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn string_pad_start() -> Self {
        Self {
            kind: BuiltinFunctionKind::StringPadStart,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn string_pad_end() -> Self {
        Self {
            kind: BuiltinFunctionKind::StringPadEnd,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn number_to_fixed() -> Self {
        Self {
            kind: BuiltinFunctionKind::NumberToFixed,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn number_to_string() -> Self {
        Self {
            kind: BuiltinFunctionKind::NumberToString,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn number_value_of() -> Self {
        Self {
            kind: BuiltinFunctionKind::NumberValueOf,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn array_is_array() -> Self {
        Self::new_kind(BuiltinFunctionKind::ArrayIsArray)
    }

    fn array_push() -> Self {
        Self {
            kind: BuiltinFunctionKind::ArrayPush,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn array_pop() -> Self {
        Self {
            kind: BuiltinFunctionKind::ArrayPop,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn array_shift() -> Self {
        Self {
            kind: BuiltinFunctionKind::ArrayShift,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn array_unshift() -> Self {
        Self {
            kind: BuiltinFunctionKind::ArrayUnshift,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn array_index_of() -> Self {
        Self {
            kind: BuiltinFunctionKind::ArrayIndexOf,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn array_includes() -> Self {
        Self {
            kind: BuiltinFunctionKind::ArrayIncludes,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn array_reverse() -> Self {
        Self {
            kind: BuiltinFunctionKind::ArrayReverse,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn array_to_reversed() -> Self {
        Self {
            kind: BuiltinFunctionKind::ArrayToReversed,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn array_to_sorted() -> Self {
        Self {
            kind: BuiltinFunctionKind::ArrayToSorted,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn array_with() -> Self {
        Self {
            kind: BuiltinFunctionKind::ArrayWith,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn array_to_spliced() -> Self {
        Self {
            kind: BuiltinFunctionKind::ArrayToSpliced,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn array_fill() -> Self {
        Self {
            kind: BuiltinFunctionKind::ArrayFill,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn array_at() -> Self {
        Self {
            kind: BuiltinFunctionKind::ArrayAt,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn array_flat() -> Self {
        Self {
            kind: BuiltinFunctionKind::ArrayFlat,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn array_join() -> Self {
        Self {
            kind: BuiltinFunctionKind::ArrayJoin,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn array_to_string() -> Self {
        Self {
            kind: BuiltinFunctionKind::ArrayToString,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn array_for_each() -> Self {
        Self {
            kind: BuiltinFunctionKind::ArrayForEach,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn array_map() -> Self {
        Self {
            kind: BuiltinFunctionKind::ArrayMap,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn array_filter() -> Self {
        Self {
            kind: BuiltinFunctionKind::ArrayFilter,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn array_find() -> Self {
        Self {
            kind: BuiltinFunctionKind::ArrayFind,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn array_find_index() -> Self {
        Self {
            kind: BuiltinFunctionKind::ArrayFindIndex,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn array_find_last() -> Self {
        Self {
            kind: BuiltinFunctionKind::ArrayFindLast,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn array_find_last_index() -> Self {
        Self {
            kind: BuiltinFunctionKind::ArrayFindLastIndex,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn array_flat_map() -> Self {
        Self {
            kind: BuiltinFunctionKind::ArrayFlatMap,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn array_copy_within() -> Self {
        Self {
            kind: BuiltinFunctionKind::ArrayCopyWithin,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn array_some() -> Self {
        Self {
            kind: BuiltinFunctionKind::ArraySome,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn array_every() -> Self {
        Self {
            kind: BuiltinFunctionKind::ArrayEvery,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn array_reduce() -> Self {
        Self {
            kind: BuiltinFunctionKind::ArrayReduce,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn array_reduce_right() -> Self {
        Self {
            kind: BuiltinFunctionKind::ArrayReduceRight,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn array_sort() -> Self {
        Self {
            kind: BuiltinFunctionKind::ArraySort,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn array_concat() -> Self {
        Self {
            kind: BuiltinFunctionKind::ArrayConcat,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn array_slice_method() -> Self {
        Self {
            kind: BuiltinFunctionKind::ArraySliceMethod,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn array_last_index_of() -> Self {
        Self {
            kind: BuiltinFunctionKind::ArrayLastIndexOf,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn array_splice() -> Self {
        Self {
            kind: BuiltinFunctionKind::ArraySplice,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn array_entries() -> Self {
        Self {
            kind: BuiltinFunctionKind::ArrayEntries,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn array_keys() -> Self {
        Self {
            kind: BuiltinFunctionKind::ArrayKeys,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn array_values() -> Self {
        Self {
            kind: BuiltinFunctionKind::ArrayValues,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    /// `RegExp.prototype[@@match]` and its siblings; `key` is a
    /// [`REGEXP_SYMBOL_METHODS`] key such as `"@@split"`.
    fn regexp_symbol_method(key: &str) -> Self {
        Self {
            kind: BuiltinFunctionKind::RegExpSymbolMethod,
            module_specifier: BuiltinModuleSpecifier::from_nonempty(key),
            iterator_handle: None,
            bound_object: None,
        }
    }

    /// `%TypedArray%.from` or `%TypedArray%.of` (`method` is "from" / "of").
    fn typed_array_static(method: &str) -> Self {
        Self {
            kind: BuiltinFunctionKind::TypedArrayStaticMethod,
            module_specifier: BuiltinModuleSpecifier::from_nonempty(method),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn map_set() -> Self {
        Self {
            kind: BuiltinFunctionKind::MapSet,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn map_get() -> Self {
        Self {
            kind: BuiltinFunctionKind::MapGet,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn map_has() -> Self {
        Self {
            kind: BuiltinFunctionKind::MapHas,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn map_delete() -> Self {
        Self {
            kind: BuiltinFunctionKind::MapDelete,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn set_add() -> Self {
        Self {
            kind: BuiltinFunctionKind::SetAdd,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn set_has() -> Self {
        Self {
            kind: BuiltinFunctionKind::SetHas,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn set_delete() -> Self {
        Self {
            kind: BuiltinFunctionKind::SetDelete,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn map_clear() -> Self {
        Self {
            kind: BuiltinFunctionKind::MapClear,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn set_clear() -> Self {
        Self {
            kind: BuiltinFunctionKind::SetClear,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn date_get_time() -> Self {
        Self {
            kind: BuiltinFunctionKind::DateGetTime,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    /// bd-3894s slice (2b): `ClientRequest.prototype.write`.
    fn client_request_write() -> Self {
        Self {
            kind: BuiltinFunctionKind::ClientRequestWrite,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    /// bd-3894s slice (2b): `ClientRequest.prototype.end`.
    fn client_request_end() -> Self {
        Self {
            kind: BuiltinFunctionKind::ClientRequestEnd,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    /// bd-3894s slice (2d): `EventEmitter.prototype.on` for the HTTP stream objects.
    fn emitter_on() -> Self {
        Self {
            kind: BuiltinFunctionKind::EmitterOn,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn performance_now() -> Self {
        Self {
            kind: BuiltinFunctionKind::PerformanceNow,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn data_view_get_uint8() -> Self {
        Self {
            kind: BuiltinFunctionKind::DataViewGetUint8,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn data_view_set_uint8() -> Self {
        Self {
            kind: BuiltinFunctionKind::DataViewSetUint8,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn data_view_get_int32() -> Self {
        Self {
            kind: BuiltinFunctionKind::DataViewGetInt32,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn data_view_set_int32() -> Self {
        Self {
            kind: BuiltinFunctionKind::DataViewSetInt32,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn data_view_get_uint32() -> Self {
        Self {
            kind: BuiltinFunctionKind::DataViewGetUint32,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn data_view_set_uint32() -> Self {
        Self {
            kind: BuiltinFunctionKind::DataViewSetUint32,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn typed_array_set() -> Self {
        Self {
            kind: BuiltinFunctionKind::TypedArraySet,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn typed_array_subarray() -> Self {
        Self {
            kind: BuiltinFunctionKind::TypedArraySubarray,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn typed_array_slice() -> Self {
        Self {
            kind: BuiltinFunctionKind::TypedArraySlice,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn typed_array_fill() -> Self {
        Self {
            kind: BuiltinFunctionKind::TypedArrayFill,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn typed_array_copy_within() -> Self {
        Self {
            kind: BuiltinFunctionKind::TypedArrayCopyWithin,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn typed_array_entries() -> Self {
        Self {
            kind: BuiltinFunctionKind::TypedArrayEntries,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn typed_array_keys() -> Self {
        Self {
            kind: BuiltinFunctionKind::TypedArrayKeys,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn typed_array_values() -> Self {
        Self {
            kind: BuiltinFunctionKind::TypedArrayValues,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    #[cfg(test)]
    fn typed_array_unsupported_method() -> Self {
        Self {
            kind: BuiltinFunctionKind::TypedArrayUnsupportedMethod,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn promise_resolve() -> Self {
        Self {
            kind: BuiltinFunctionKind::PromiseResolve,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn promise_reject() -> Self {
        Self {
            kind: BuiltinFunctionKind::PromiseReject,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn promise_all() -> Self {
        Self {
            kind: BuiltinFunctionKind::PromiseAll,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn promise_race() -> Self {
        Self {
            kind: BuiltinFunctionKind::PromiseRace,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn promise_all_settled() -> Self {
        Self {
            kind: BuiltinFunctionKind::PromiseAllSettled,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn promise_any() -> Self {
        Self {
            kind: BuiltinFunctionKind::PromiseAny,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn promise_then() -> Self {
        Self {
            kind: BuiltinFunctionKind::PromiseThen,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn promise_catch() -> Self {
        Self {
            kind: BuiltinFunctionKind::PromiseCatch,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn promise_with_resolvers() -> Self {
        Self::new_kind(BuiltinFunctionKind::PromiseWithResolvers)
    }

    fn promise_finally() -> Self {
        Self {
            kind: BuiltinFunctionKind::PromiseFinally,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn console_log() -> Self {
        Self {
            kind: BuiltinFunctionKind::ConsoleLog,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn console_error() -> Self {
        Self {
            kind: BuiltinFunctionKind::ConsoleError,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn console_warn() -> Self {
        Self {
            kind: BuiltinFunctionKind::ConsoleWarn,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn console_info() -> Self {
        Self {
            kind: BuiltinFunctionKind::ConsoleInfo,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn console_method(method: &str) -> Self {
        Self {
            kind: BuiltinFunctionKind::ConsoleMethod,
            module_specifier: BuiltinModuleSpecifier::from_nonempty(method),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn object_proto_setter() -> Self {
        Self::new_kind(BuiltinFunctionKind::ObjectProtoSetter)
    }

    fn proxy_revoke(proxy_id: ObjectId) -> Self {
        Self {
            kind: BuiltinFunctionKind::ProxyRevoke,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: Some(proxy_id.0),
        }
    }

    fn regexp_test() -> Self {
        Self {
            kind: BuiltinFunctionKind::RegExpTest,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn object_has_own_property() -> Self {
        Self {
            kind: BuiltinFunctionKind::ObjectHasOwnProperty,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn object_property_is_enumerable() -> Self {
        Self {
            kind: BuiltinFunctionKind::ObjectPrototypePropertyIsEnumerable,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn object_value_of() -> Self {
        Self {
            kind: BuiltinFunctionKind::ObjectPrototypeValueOf,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn object_to_string() -> Self {
        Self {
            kind: BuiltinFunctionKind::ObjectPrototypeToString,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: None,
        }
    }

    fn display_name(&self) -> &'static str {
        match self.kind {
            BuiltinFunctionKind::Require => "require",
            BuiltinFunctionKind::ModuleCreateRequire => "createRequire",
            BuiltinFunctionKind::RequireResolve | BuiltinFunctionKind::ImportMetaResolve => {
                "resolve"
            }
            BuiltinFunctionKind::FunctionConstructor => "Function",
            BuiltinFunctionKind::FunctionPrototype => "",
            BuiltinFunctionKind::NativeTimerPromisesGetter => "get",
            BuiltinFunctionKind::GeneratedFunction => "anonymous",
            BuiltinFunctionKind::IteratorNext
            | BuiltinFunctionKind::GeneratorNext
            | BuiltinFunctionKind::AsyncGeneratorNext => "next",
            BuiltinFunctionKind::GeneratorReturn | BuiltinFunctionKind::AsyncGeneratorReturn => {
                "return"
            }
            BuiltinFunctionKind::GeneratorThrow | BuiltinFunctionKind::AsyncGeneratorThrow => {
                "throw"
            }
            BuiltinFunctionKind::AsyncGeneratorIteratorSelf => "@@asyncIterator",
            BuiltinFunctionKind::IteratorSelf => "@@iterator",
            BuiltinFunctionKind::ConsoleLog => "log",
            BuiltinFunctionKind::ConsoleError => "error",
            BuiltinFunctionKind::ConsoleWarn => "warn",
            BuiltinFunctionKind::ConsoleInfo => "info",
            BuiltinFunctionKind::ConsoleMethod => CONSOLE_EXTRA_METHODS
                .iter()
                .copied()
                .find(|method| self.module_specifier.0.as_deref() == Some(*method))
                .unwrap_or("log"),
            BuiltinFunctionKind::SetMethod => set_algebra::SET_ALGEBRA_METHODS
                .iter()
                .copied()
                .find(|method| self.module_specifier.0.as_deref() == Some(*method))
                .unwrap_or("union"),
            BuiltinFunctionKind::StringCharAt => "charAt",
            BuiltinFunctionKind::StringCharCodeAt => "charCodeAt",
            BuiltinFunctionKind::StringAt => "at",
            BuiltinFunctionKind::StringToUpperCase
                if self.module_specifier.0.as_deref() == Some("toLocaleUpperCase") =>
            {
                "toLocaleUpperCase"
            }
            BuiltinFunctionKind::StringToLowerCase
                if self.module_specifier.0.as_deref() == Some("toLocaleLowerCase") =>
            {
                "toLocaleLowerCase"
            }
            BuiltinFunctionKind::StringToUpperCase => "toUpperCase",
            BuiltinFunctionKind::StringToLowerCase => "toLowerCase",
            BuiltinFunctionKind::StringTrim => "trim",
            BuiltinFunctionKind::StringSplit => "split",
            BuiltinFunctionKind::StringIncludes => "includes",
            BuiltinFunctionKind::StringStartsWith => "startsWith",
            BuiltinFunctionKind::StringEndsWith => "endsWith",
            BuiltinFunctionKind::StringIndexOf => "indexOf",
            BuiltinFunctionKind::StringLastIndexOf => "lastIndexOf",
            BuiltinFunctionKind::StringSlice => "slice",
            BuiltinFunctionKind::StringSubstring => "substring",
            BuiltinFunctionKind::StringSubstr => "substr",
            BuiltinFunctionKind::StringReplace => "replace",
            BuiltinFunctionKind::StringMatch => "match",
            BuiltinFunctionKind::StringMatchAll => "matchAll",
            BuiltinFunctionKind::StringSearch => "search",
            BuiltinFunctionKind::StringRepeat => "repeat",
            BuiltinFunctionKind::StringPadStart => "padStart",
            BuiltinFunctionKind::StringPadEnd => "padEnd",
            BuiltinFunctionKind::StringTrimStart => "trimStart",
            BuiltinFunctionKind::StringTrimEnd => "trimEnd",
            BuiltinFunctionKind::StringReplaceAll => "replaceAll",
            BuiltinFunctionKind::StringCodePointAt => "codePointAt",
            BuiltinFunctionKind::StringLocaleCompare => "localeCompare",
            BuiltinFunctionKind::StringNormalize => "normalize",
            BuiltinFunctionKind::NumberToFixed => "toFixed",
            BuiltinFunctionKind::NumberToString => "toString",
            BuiltinFunctionKind::NumberValueOf => "valueOf",
            BuiltinFunctionKind::BooleanPrototypeToString => "toString",
            BuiltinFunctionKind::BooleanPrototypeValueOf => "valueOf",
            BuiltinFunctionKind::SymbolPrototypeToString => "toString",
            BuiltinFunctionKind::SymbolPrototypeValueOf => "valueOf",
            BuiltinFunctionKind::SymbolPrototypeToPrimitive
            | BuiltinFunctionKind::DatePrototypeToPrimitive => "[Symbol.toPrimitive]",
            BuiltinFunctionKind::FunctionPrototypeHasInstance => "[Symbol.hasInstance]",
            BuiltinFunctionKind::RegExpPrototypeCompile => "compile",
            BuiltinFunctionKind::SharedArrayBufferMethod => {
                match self.module_specifier.0.as_deref() {
                    Some("grow") => "grow",
                    _ => "slice",
                }
            }
            BuiltinFunctionKind::ArrayBufferMethod => resizable_buffers::ARRAY_BUFFER_METHODS
                .iter()
                .copied()
                .find(|name| self.module_specifier.0.as_deref() == Some(*name))
                .unwrap_or("resize"),
            BuiltinFunctionKind::AtomicsMethod => atomics::ATOMICS_METHODS
                .iter()
                .copied()
                .find(|name| self.module_specifier.0.as_deref() == Some(*name))
                .unwrap_or(""),
            BuiltinFunctionKind::BlobMethod => blob::BLOB_METHODS
                .iter()
                .copied()
                .find(|name| self.module_specifier.0.as_deref() == Some(*name))
                .unwrap_or(""),
            BuiltinFunctionKind::StringIterator | BuiltinFunctionKind::GeneratorIteratorSelf => {
                "@@iterator"
            }
            BuiltinFunctionKind::ProxyRevoke => "revoke",
            BuiltinFunctionKind::ObjectProtoSetter => "set __proto__",
            BuiltinFunctionKind::CallableProxy => "",
            BuiltinFunctionKind::UrlMethod => {
                if self.module_specifier.0.as_deref() == Some("toJSON") {
                    "toJSON"
                } else {
                    "toString"
                }
            }
            BuiltinFunctionKind::EventTargetMethod => event_target::EVENT_TARGET_METHODS
                .iter()
                .find(|(specifier, _, _)| self.module_specifier.0.as_deref() == Some(*specifier))
                .map_or("", |(_, _, name)| *name),
            BuiltinFunctionKind::IteratorHelperMethod => iterator_helpers::ITERATOR_HELPER_METHODS
                .iter()
                .find(|(specifier, _, _)| self.module_specifier.0.as_deref() == Some(*specifier))
                .map_or("", |(_, _, name)| *name),
            BuiltinFunctionKind::StringHtmlMethod => STRING_HTML_METHODS
                .iter()
                .find(|(name, _, _)| self.module_specifier.0.as_deref() == Some(*name))
                .map_or("", |(name, _, _)| *name),
            BuiltinFunctionKind::UrlStatic => {
                if self.module_specifier.0.as_deref() == Some("parse") {
                    "parse"
                } else {
                    "canParse"
                }
            }
            BuiltinFunctionKind::ObjectLegacyAccessor => object_integrity::LEGACY_ACCESSOR_METHODS
                .iter()
                .copied()
                .find(|method| self.module_specifier.0.as_deref() == Some(*method))
                .unwrap_or("__defineGetter__"),
            BuiltinFunctionKind::ArrayIsArray => "isArray",
            BuiltinFunctionKind::StreamReadablePause => "pause",
            BuiltinFunctionKind::StreamReadableResume => "resume",
            BuiltinFunctionKind::StreamReadableIsPaused => "isPaused",
            BuiltinFunctionKind::StreamReadablePush => "push",
            BuiltinFunctionKind::StreamReadableToArray => "toArray",
            BuiltinFunctionKind::StreamReadableRead => "read",
            BuiltinFunctionKind::StreamReadableUnshift => "unshift",
            BuiltinFunctionKind::StreamReadablePipe => "pipe",
            BuiltinFunctionKind::StreamReadableUnpipe => "unpipe",
            BuiltinFunctionKind::StreamReadablePipeData => "ondata",
            BuiltinFunctionKind::StreamReadablePipeEnd => "onend",
            BuiltinFunctionKind::StreamReadableSetEncoding => "setEncoding",
            BuiltinFunctionKind::StreamReadableDestroy => "destroy",
            BuiltinFunctionKind::StreamWritableWrite => "write",
            BuiltinFunctionKind::StreamWritableEnd => "end",
            BuiltinFunctionKind::StreamWritableWriteDone
            | BuiltinFunctionKind::StreamWritableFinalDone => "callback",
            BuiltinFunctionKind::StreamWritableCork => "cork",
            BuiltinFunctionKind::StreamWritableUncork => "uncork",
            BuiltinFunctionKind::StreamWritableDestroy => "destroy",
            BuiltinFunctionKind::StreamPassThroughWrite => "_write",
            BuiltinFunctionKind::StreamPassThroughFinal => "_final",
            BuiltinFunctionKind::StreamPassThroughDestroy => "destroy",
            BuiltinFunctionKind::StreamTransformWriteDone
            | BuiltinFunctionKind::StreamTransformFinalDone => "callback",
            BuiltinFunctionKind::StreamTransformFinal => "_final",
            BuiltinFunctionKind::StreamPipelineFinish => "onfinish",
            BuiltinFunctionKind::StreamPipelineError => "onerror",
            BuiltinFunctionKind::UrlSearchParamsGet => "get",
            BuiltinFunctionKind::UrlSearchParamsHas => "has",
            BuiltinFunctionKind::UrlSearchParamsGetAll => "getAll",
            BuiltinFunctionKind::UrlSearchParamsAppend => "append",
            BuiltinFunctionKind::UrlSearchParamsSort => "sort",
            BuiltinFunctionKind::UrlSearchParamsDelete => "delete",
            BuiltinFunctionKind::UrlSearchParamsSet => "set",
            BuiltinFunctionKind::UrlSearchParamsToString => "toString",
            BuiltinFunctionKind::UrlSearchParamsKeys => "keys",
            BuiltinFunctionKind::UrlSearchParamsValues => "values",
            BuiltinFunctionKind::UrlSearchParamsEntries => "entries",
            BuiltinFunctionKind::UrlSearchParamsForEach => "forEach",
            BuiltinFunctionKind::NetServerListen => "listen",
            BuiltinFunctionKind::NetServerAddress => "address",
            BuiltinFunctionKind::NetServerClose => "close",
            BuiltinFunctionKind::NetSocketWrite => "write",
            BuiltinFunctionKind::NetSocketEnd => "end",
            BuiltinFunctionKind::NetSocketDestroy => "destroy",
            BuiltinFunctionKind::NetSocketSetEncoding => "setEncoding",
            BuiltinFunctionKind::NetSocketPause => "pause",
            BuiltinFunctionKind::NetSocketResume => "resume",
            BuiltinFunctionKind::NetSocketRef => "ref",
            BuiltinFunctionKind::NetSocketUnref => "unref",
            BuiltinFunctionKind::NetSocketSetNoDelay => "setNoDelay",
            BuiltinFunctionKind::NetSocketSetKeepAlive => "setKeepAlive",
            BuiltinFunctionKind::HttpClientRequestWrite
            | BuiltinFunctionKind::HttpServerResponseWrite => "write",
            BuiltinFunctionKind::HttpClientRequestEnd
            | BuiltinFunctionKind::HttpServerResponseEnd => "end",
            BuiltinFunctionKind::ChildProcessKill => "kill",
            BuiltinFunctionKind::ChildProcessStdinWrite => "write",
            BuiltinFunctionKind::ChildProcessStdinEnd => "end",
            BuiltinFunctionKind::HttpClientRequestSetHeader
            | BuiltinFunctionKind::HttpServerResponseSetHeader => "setHeader",
            BuiltinFunctionKind::HttpIncomingMessageSetEncoding => "setEncoding",
            BuiltinFunctionKind::HttpIncomingMessageResume => "resume",
            BuiltinFunctionKind::HttpServerResponseGetHeader => "getHeader",
            BuiltinFunctionKind::HttpServerResponseHasHeader => "hasHeader",
            BuiltinFunctionKind::HttpServerResponseRemoveHeader => "removeHeader",
            BuiltinFunctionKind::HttpServerResponseWriteHead => "writeHead",
            BuiltinFunctionKind::TlsSocketGetPeerCertificate => "getPeerCertificate",
            BuiltinFunctionKind::TlsSocketGetProtocol => "getProtocol",
            BuiltinFunctionKind::TlsSocketGetCipher => "getCipher",
            BuiltinFunctionKind::TlsSocketIsSessionReused => "isSessionReused",
            BuiltinFunctionKind::TlsSocketGetSession => "getSession",
            BuiltinFunctionKind::ArrayPush => "push",
            BuiltinFunctionKind::ArrayPop => "pop",
            BuiltinFunctionKind::ArrayShift => "shift",
            BuiltinFunctionKind::ArrayUnshift => "unshift",
            BuiltinFunctionKind::ArrayIndexOf => "indexOf",
            BuiltinFunctionKind::ArrayIncludes => "includes",
            BuiltinFunctionKind::ArrayReverse => "reverse",
            BuiltinFunctionKind::ArrayFill => "fill",
            BuiltinFunctionKind::ArrayAt => "at",
            BuiltinFunctionKind::ArrayFlat => "flat",
            BuiltinFunctionKind::ArrayJoin => "join",
            BuiltinFunctionKind::ArrayToLocaleString => "toLocaleString",
            BuiltinFunctionKind::ArrayToString => "toString",
            BuiltinFunctionKind::ArrayForEach => "forEach",
            BuiltinFunctionKind::ArrayMap => "map",
            BuiltinFunctionKind::ArrayFilter => "filter",
            BuiltinFunctionKind::ArrayFind => "find",
            BuiltinFunctionKind::ArrayFindIndex => "findIndex",
            BuiltinFunctionKind::ArrayFindLast => "findLast",
            BuiltinFunctionKind::ArrayFindLastIndex => "findLastIndex",
            BuiltinFunctionKind::ArrayFlatMap => "flatMap",
            BuiltinFunctionKind::ArrayCopyWithin => "copyWithin",
            BuiltinFunctionKind::ArraySome => "some",
            BuiltinFunctionKind::ArrayEvery => "every",
            BuiltinFunctionKind::ArrayReduce => "reduce",
            BuiltinFunctionKind::ArrayReduceRight => "reduceRight",
            BuiltinFunctionKind::ArraySort => "sort",
            BuiltinFunctionKind::ArrayConcat => "concat",
            BuiltinFunctionKind::ArraySliceMethod => "slice",
            BuiltinFunctionKind::ArrayLastIndexOf => "lastIndexOf",
            BuiltinFunctionKind::ArraySplice => "splice",
            BuiltinFunctionKind::ArrayToReversed => "toReversed",
            BuiltinFunctionKind::ArrayToSorted => "toSorted",
            BuiltinFunctionKind::ArrayWith => "with",
            BuiltinFunctionKind::ArrayToSpliced => "toSpliced",
            BuiltinFunctionKind::ArrayEntries => "entries",
            BuiltinFunctionKind::ArrayKeys => "keys",
            BuiltinFunctionKind::ArrayValues => "values",
            BuiltinFunctionKind::MapSet => "set",
            BuiltinFunctionKind::MapGet => "get",
            BuiltinFunctionKind::MapHas => "has",
            BuiltinFunctionKind::MapDelete => "delete",
            BuiltinFunctionKind::SetAdd => "add",
            BuiltinFunctionKind::SetHas => "has",
            BuiltinFunctionKind::SetDelete => "delete",
            BuiltinFunctionKind::MapClear => "clear",
            BuiltinFunctionKind::SetClear => "clear",
            BuiltinFunctionKind::DateGetTime => "getTime",
            BuiltinFunctionKind::ClientRequestWrite => "write",
            BuiltinFunctionKind::ClientRequestEnd => "end",
            BuiltinFunctionKind::EmitterOn => "on",
            BuiltinFunctionKind::PerformanceNow => "now",
            BuiltinFunctionKind::DataViewGetUint8 => "getUint8",
            BuiltinFunctionKind::DataViewSetUint8 => "setUint8",
            BuiltinFunctionKind::DataViewGetInt32 => "getInt32",
            BuiltinFunctionKind::DataViewSetInt32 => "setInt32",
            BuiltinFunctionKind::DataViewGetUint32 => "getUint32",
            BuiltinFunctionKind::DataViewSetUint32 => "setUint32",
            BuiltinFunctionKind::TypedArraySet => "set",
            BuiltinFunctionKind::TypedArraySubarray => "subarray",
            BuiltinFunctionKind::TypedArraySlice => "slice",
            BuiltinFunctionKind::TypedArrayFill => "fill",
            BuiltinFunctionKind::TypedArrayCopyWithin => "copyWithin",
            BuiltinFunctionKind::TypedArrayEntries => "entries",
            BuiltinFunctionKind::TypedArrayKeys => "keys",
            BuiltinFunctionKind::TypedArrayValues => "values",
            BuiltinFunctionKind::TypedArrayUnsupportedMethod => "unsupportedTypedArrayMethod",
            BuiltinFunctionKind::BufferToString => "toString",
            BuiltinFunctionKind::BufferSharedSlice => "slice",
            BuiltinFunctionKind::BufferIndexOf => "indexOf",
            BuiltinFunctionKind::BufferIncludes => "includes",
            BuiltinFunctionKind::BufferEquals => "equals",
            BuiltinFunctionKind::BufferCompare => "compare",
            BuiltinFunctionKind::BufferReadUInt8 => "readUInt8",
            BuiltinFunctionKind::BufferWriteUInt8 => "writeUInt8",
            BuiltinFunctionKind::BufferReadUInt16Le => "readUInt16LE",
            BuiltinFunctionKind::BufferReadUInt16Be => "readUInt16BE",
            BuiltinFunctionKind::BufferWriteUInt16Le => "writeUInt16LE",
            BuiltinFunctionKind::BufferWriteUInt16Be => "writeUInt16BE",
            BuiltinFunctionKind::BufferReadInt32Le => "readInt32LE",
            BuiltinFunctionKind::BufferReadInt32Be => "readInt32BE",
            BuiltinFunctionKind::BufferWriteInt32Le => "writeInt32LE",
            BuiltinFunctionKind::BufferWriteInt32Be => "writeInt32BE",
            BuiltinFunctionKind::BufferReadUInt32Le => "readUInt32LE",
            BuiltinFunctionKind::BufferReadUInt32Be => "readUInt32BE",
            BuiltinFunctionKind::BufferWriteUInt32Le => "writeUInt32LE",
            BuiltinFunctionKind::BufferWriteUInt32Be => "writeUInt32BE",
            BuiltinFunctionKind::BufferCopy => "copy",
            BuiltinFunctionKind::BufferToJson => "toJSON",
            BuiltinFunctionKind::BufferSwap16 => "swap16",
            BuiltinFunctionKind::BufferSwap32 => "swap32",
            BuiltinFunctionKind::BufferSwap64 => "swap64",
            BuiltinFunctionKind::PromiseResolve => "resolve",
            BuiltinFunctionKind::PromiseReject => "reject",
            BuiltinFunctionKind::PromiseAll => "all",
            BuiltinFunctionKind::PromiseRace => "race",
            BuiltinFunctionKind::PromiseAllSettled => "allSettled",
            BuiltinFunctionKind::PromiseWithResolvers => "withResolvers",
            BuiltinFunctionKind::PromiseAny => "any",
            BuiltinFunctionKind::PromiseThen => "then",
            BuiltinFunctionKind::PromiseCatch => "catch",
            BuiltinFunctionKind::PromiseFinally => "finally",
            BuiltinFunctionKind::PromiseCapabilityExecutor
            | BuiltinFunctionKind::PromiseAllResolveElement
            | BuiltinFunctionKind::PromiseAllSettledResolveElement
            | BuiltinFunctionKind::PromiseAllSettledRejectElement
            | BuiltinFunctionKind::PromiseAnyRejectElement => "",
            BuiltinFunctionKind::RegExpTest => "test",
            BuiltinFunctionKind::ObjectHasOwnProperty => "hasOwnProperty",
            BuiltinFunctionKind::ObjectPrototypePropertyIsEnumerable => "propertyIsEnumerable",
            BuiltinFunctionKind::ObjectPrototypeValueOf => "valueOf",
            BuiltinFunctionKind::ObjectPrototypeToString => "toString",
            BuiltinFunctionKind::StringIsWellFormed => "isWellFormed",
            BuiltinFunctionKind::StringToWellFormed => "toWellFormed",
            BuiltinFunctionKind::StringToString => "toString",
            BuiltinFunctionKind::StringValueOf => "valueOf",
            BuiltinFunctionKind::SetTimeout => "setTimeout",
            BuiltinFunctionKind::ClearTimeout => "clearTimeout",
            BuiltinFunctionKind::SetInterval => "setInterval",
            BuiltinFunctionKind::ClearInterval => "clearInterval",
            BuiltinFunctionKind::SetImmediate => "setImmediate",
            BuiltinFunctionKind::ClearImmediate => "clearImmediate",
            BuiltinFunctionKind::QueueMicrotask => "queueMicrotask",
            BuiltinFunctionKind::TimerHasRef => "hasRef",
            BuiltinFunctionKind::TimerRef => "ref",
            BuiltinFunctionKind::TimerUnref => "unref",
            BuiltinFunctionKind::FsStatsIsFile | BuiltinFunctionKind::FsDirentIsFile => "isFile",
            BuiltinFunctionKind::FsStatsIsDirectory | BuiltinFunctionKind::FsDirentIsDirectory => {
                "isDirectory"
            }
            BuiltinFunctionKind::FsEntryIsSymbolicLink => "isSymbolicLink",
            BuiltinFunctionKind::EmitterOnce => "once",
            BuiltinFunctionKind::EmitterOff => "removeListener",
            BuiltinFunctionKind::EmitterRemoveAllListeners => "removeAllListeners",
            BuiltinFunctionKind::EmitterListenerCount => "listenerCount",
            BuiltinFunctionKind::EmitterEventNames => "eventNames",
            BuiltinFunctionKind::EmitterPrependListener => "prependListener",
            BuiltinFunctionKind::EmitterPrependOnceListener => "prependOnceListener",
            BuiltinFunctionKind::EmitterEmit => "emit",
            BuiltinFunctionKind::EmitterGetMaxListeners => "getMaxListeners",
            BuiltinFunctionKind::EmitterSetMaxListeners => "setMaxListeners",
            BuiltinFunctionKind::EmitterListeners => "listeners",
            BuiltinFunctionKind::ClusterSetup => "setupPrimary",
            BuiltinFunctionKind::ClusterDisconnect => "disconnect",
            BuiltinFunctionKind::ClusterFork => "fork",
            BuiltinFunctionKind::ClusterWorker => "Worker",
            BuiltinFunctionKind::CryptoUpdate | BuiltinFunctionKind::CryptoCipherUpdate => "update",
            BuiltinFunctionKind::CryptoDigest => "digest",
            BuiltinFunctionKind::CryptoCopy => "copy",
            BuiltinFunctionKind::CryptoCipherFinal => "final",
            BuiltinFunctionKind::CryptoGetAuthTag => "getAuthTag",
            BuiltinFunctionKind::CryptoSetAuthTag => "setAuthTag",
            BuiltinFunctionKind::DateConstructor => "Date",
            BuiltinFunctionKind::PromiseConstructor => "Promise",
            BuiltinFunctionKind::DateNow => "now",
            BuiltinFunctionKind::MathAbs => "abs",
            BuiltinFunctionKind::MathCeil => "ceil",
            BuiltinFunctionKind::MathFloor => "floor",
            BuiltinFunctionKind::MathRound => "round",
            BuiltinFunctionKind::MathMax => "max",
            BuiltinFunctionKind::MathMin => "min",
            BuiltinFunctionKind::MathRandom => "random",
            BuiltinFunctionKind::MathPow => "pow",
            BuiltinFunctionKind::MathSqrt => "sqrt",
            BuiltinFunctionKind::MathSin => "sin",
            BuiltinFunctionKind::MathCos => "cos",
            BuiltinFunctionKind::MathLog => "log",
            BuiltinFunctionKind::MathExp => "exp",
            BuiltinFunctionKind::MathTan => "tan",
            BuiltinFunctionKind::MathTrunc => "trunc",
            BuiltinFunctionKind::MathSign => "sign",
            BuiltinFunctionKind::MathAtan2 => "atan2",
            BuiltinFunctionKind::MathAsin => "asin",
            BuiltinFunctionKind::MathAcos => "acos",
            BuiltinFunctionKind::MathHypot => "hypot",
            BuiltinFunctionKind::MathImul => "imul",
            BuiltinFunctionKind::MathAtan => "atan",
            BuiltinFunctionKind::MathLog10 => "log10",
            BuiltinFunctionKind::MathLog2 => "log2",
            BuiltinFunctionKind::MathCbrt => "cbrt",
            BuiltinFunctionKind::MathClz32 => "clz32",
            BuiltinFunctionKind::MathFround => "fround",
            BuiltinFunctionKind::MathAcosh => "acosh",
            BuiltinFunctionKind::MathSinh => "sinh",
            BuiltinFunctionKind::MathCosh => "cosh",
            BuiltinFunctionKind::MathTanh => "tanh",
            BuiltinFunctionKind::MathExpm1 => "expm1",
            BuiltinFunctionKind::MathLog1p => "log1p",
            BuiltinFunctionKind::MathAsinh => "asinh",
            BuiltinFunctionKind::MathAtanh => "atanh",
            BuiltinFunctionKind::EmitterRawListeners => "rawListeners",
            BuiltinFunctionKind::EmitterOnceWrapper => "onceWrapper",
            BuiltinFunctionKind::EventEmitterConstructor => "EventEmitter",
            BuiltinFunctionKind::FunctionPrototypeCall => "call",
            BuiltinFunctionKind::FunctionPrototypeApply => "apply",
            BuiltinFunctionKind::FunctionPrototypeBind => "bind",
            BuiltinFunctionKind::BoundFunction => "bound",
            BuiltinFunctionKind::MapForEach | BuiltinFunctionKind::SetForEach => "forEach",
            BuiltinFunctionKind::MapKeys => "keys",
            BuiltinFunctionKind::MapValues | BuiltinFunctionKind::SetValues => "values",
            BuiltinFunctionKind::MapEntries | BuiltinFunctionKind::SetEntries => "entries",
            BuiltinFunctionKind::StringPrototypeConcat => "concat",
            BuiltinFunctionKind::NumberToPrecision => "toPrecision",
            BuiltinFunctionKind::NumberToExponential => "toExponential",
            BuiltinFunctionKind::NumberToLocaleString => "toLocaleString",
            BuiltinFunctionKind::IntlConstructor => [
                "NumberFormat",
                "DateTimeFormat",
                "Collator",
                "PluralRules",
                "RelativeTimeFormat",
                "ListFormat",
                "Segmenter",
            ]
            .iter()
            .copied()
            .find(|name| self.module_specifier.0.as_deref() == Some(*name))
            .unwrap_or("IntlConstructor"),
            BuiltinFunctionKind::IntlMethod
                if self.module_specifier.0.as_deref() == Some("Segments.iterator") =>
            {
                "[Symbol.iterator]"
            }
            BuiltinFunctionKind::IntlMethod => [
                "format",
                "formatToParts",
                "compare",
                "select",
                "resolvedOptions",
                "segment",
                "containing",
            ]
            .iter()
            .copied()
            .find(|name| {
                self.module_specifier
                    .0
                    .as_deref()
                    .and_then(|specifier| specifier.split_once('.'))
                    .is_some_and(|(_, method)| method == *name)
            })
            .unwrap_or("intlMethod"),
            BuiltinFunctionKind::IntlGetCanonicalLocales => "getCanonicalLocales",
            BuiltinFunctionKind::RegExpPrototypeExec => "exec",
            BuiltinFunctionKind::DateUtc => "UTC",
            BuiltinFunctionKind::DateParse => "parse",
            BuiltinFunctionKind::TimersPromisesIntervalNext => "next",
            BuiltinFunctionKind::TimersPromisesIntervalReturn => "return",
            BuiltinFunctionKind::FunctionPrototypeToString
            | BuiltinFunctionKind::RegExpPrototypeToString => "toString",
            BuiltinFunctionKind::WeakSetMethod => ["add", "has", "delete"]
                .iter()
                .copied()
                .find(|name| self.module_specifier.0.as_deref() == Some(*name))
                .unwrap_or("weakSetMethod"),
            BuiltinFunctionKind::TextCodecMethod => ["encode", "encodeInto", "decode"]
                .iter()
                .copied()
                .find(|name| self.module_specifier.0.as_deref() == Some(*name))
                .unwrap_or("textCodecMethod"),
            BuiltinFunctionKind::WeakMapMethod => ["get", "set", "has", "delete"]
                .iter()
                .copied()
                .find(|name| self.module_specifier.0.as_deref() == Some(*name))
                .unwrap_or("weakMapMethod"),
            BuiltinFunctionKind::TypedArrayMethod => TYPED_ARRAY_METHODS
                .iter()
                .copied()
                .find(|name| self.module_specifier.0.as_deref() == Some(*name))
                .unwrap_or("typedArrayMethod"),
            BuiltinFunctionKind::DataViewMethod => DATA_VIEW_METHODS
                .iter()
                .copied()
                .find(|name| self.module_specifier.0.as_deref() == Some(*name))
                .unwrap_or("dataViewMethod"),
            BuiltinFunctionKind::BufferNumericMethod => BUFFER_NUMERIC_METHODS
                .iter()
                .copied()
                .find(|name| self.module_specifier.0.as_deref() == Some(*name))
                .unwrap_or("bufferNumericMethod"),
            BuiltinFunctionKind::DatePrototypeMethod => DATE_PROTOTYPE_METHODS
                .iter()
                .copied()
                .find(|name| self.module_specifier.0.as_deref() == Some(*name))
                .unwrap_or("date"),
            BuiltinFunctionKind::StandardConstructor => {
                canonical_builtin_prototype_name(&self.module_specifier).unwrap_or("Function")
            }
            BuiltinFunctionKind::StaticHostcall => {
                static_hostcall_name(&self.module_specifier).unwrap_or("anonymous")
            }
            BuiltinFunctionKind::NativeHttpFunction => {
                native_http_function_metadata(&self.module_specifier)
                    .map_or("anonymous", |(_, name, _)| name)
            }
            BuiltinFunctionKind::NativeChildProcessFunction => {
                native_child_process_function_metadata(&self.module_specifier)
                    .map_or("anonymous", |(_, name, _)| name)
            }
            BuiltinFunctionKind::PrototypeGetter => self
                .module_specifier
                .0
                .as_deref()
                .and_then(prototype_getters::prototype_getter_entry)
                .map_or("get", |(_, _, name)| name),
            BuiltinFunctionKind::ErrorPrototypeToString => "toString",
            BuiltinFunctionKind::ErrorCaptureStackTrace => "captureStackTrace",
            BuiltinFunctionKind::ArrayBufferSlice => "slice",
            BuiltinFunctionKind::WeakRefDeref => "deref",
            BuiltinFunctionKind::FinalizationRegistryMethod => ["register", "unregister"]
                .iter()
                .copied()
                .find(|name| self.module_specifier.0.as_deref() == Some(*name))
                .unwrap_or("finalizationRegistryMethod"),
            BuiltinFunctionKind::RegExpSymbolMethod => REGEXP_SYMBOL_METHODS
                .iter()
                .map(|(name, _)| *name)
                .find(|name| self.module_specifier.0.as_deref() == Some(*name))
                .unwrap_or("@@regexp"),
            BuiltinFunctionKind::TypedArrayStaticMethod => ["from", "of"]
                .iter()
                .copied()
                .find(|name| self.module_specifier.0.as_deref() == Some(*name))
                .unwrap_or("from"),
            // Anonymous built-in closures in the spec.
            BuiltinFunctionKind::PromiseThenFinally
            | BuiltinFunctionKind::PromiseCatchFinally
            | BuiltinFunctionKind::PromiseFinallyValueThunk
            | BuiltinFunctionKind::PromiseFinallyThrower
            | BuiltinFunctionKind::ArrayFromAsyncFulfilled
            | BuiltinFunctionKind::ArrayFromAsyncRejected
            | BuiltinFunctionKind::ThrowTypeError => "",
            BuiltinFunctionKind::ObjectPrototypeIsPrototypeOf => "isPrototypeOf",
            BuiltinFunctionKind::ObjectPrototypeToLocaleString => "toLocaleString",
            BuiltinFunctionKind::BigIntToString => "toString",
            BuiltinFunctionKind::BigIntValueOf => "valueOf",
            BuiltinFunctionKind::BigIntAsUintN => "asUintN",
            BuiltinFunctionKind::BigIntAsIntN => "asIntN",
        }
    }

    /// bd-9vouw.17: the object that owns this built-in as a property, as
    /// keyed in `builtin_function_lengths` (`"Array.prototype"`, `"Math"`,
    /// `"globalThis"`, ...). `None` for engine-internal closures and Node
    /// module methods, whose `length` the engine does not model.
    fn spec_owner(&self) -> Option<&'static str> {
        use BuiltinFunctionKind as K;
        Some(match self.kind {
            K::ArrayAt
            | K::ArrayConcat
            | K::ArrayCopyWithin
            | K::ArrayEntries
            | K::ArrayEvery
            | K::ArrayFill
            | K::ArrayFilter
            | K::ArrayFind
            | K::ArrayFindIndex
            | K::ArrayFindLast
            | K::ArrayFindLastIndex
            | K::ArrayFlat
            | K::ArrayFlatMap
            | K::ArrayForEach
            | K::ArrayIncludes
            | K::ArrayIndexOf
            | K::ArrayJoin
            | K::ArrayToLocaleString
            | K::ArrayKeys
            | K::ArrayLastIndexOf
            | K::ArrayMap
            | K::ArrayPop
            | K::ArrayPush
            | K::ArrayReduce
            | K::ArrayReduceRight
            | K::ArrayReverse
            | K::ArrayShift
            | K::ArraySliceMethod
            | K::ArraySome
            | K::ArraySort
            | K::ArraySplice
            | K::ArrayToReversed
            | K::ArrayToSorted
            | K::ArrayToSpliced
            | K::ArrayToString
            | K::ArrayUnshift
            | K::ArrayValues
            | K::ArrayWith => "Array.prototype",
            K::ArrayIsArray => "Array",
            K::StringAt
            | K::StringCharAt
            | K::StringCharCodeAt
            | K::StringCodePointAt
            | K::StringEndsWith
            | K::StringIncludes
            | K::StringIndexOf
            | K::StringIsWellFormed
            | K::StringLastIndexOf
            | K::StringLocaleCompare
            | K::StringMatch
            | K::StringMatchAll
            | K::StringNormalize
            | K::StringPadEnd
            | K::StringPadStart
            | K::StringPrototypeConcat
            | K::StringRepeat
            | K::StringReplace
            | K::StringReplaceAll
            | K::StringSearch
            | K::StringSlice
            | K::StringSplit
            | K::StringStartsWith
            | K::StringSubstr
            | K::StringSubstring
            | K::StringToLowerCase
            | K::StringToString
            | K::StringValueOf
            | K::StringToUpperCase
            | K::StringToWellFormed
            | K::StringTrim
            | K::StringTrimEnd
            | K::StringTrimStart => "String.prototype",
            K::MathAbs
            | K::MathAcos
            | K::MathAcosh
            | K::MathSinh
            | K::MathCosh
            | K::MathTanh
            | K::MathExpm1
            | K::MathLog1p
            | K::MathAsin
            | K::MathAsinh
            | K::MathAtan
            | K::MathAtan2
            | K::MathAtanh
            | K::MathCbrt
            | K::MathCeil
            | K::MathClz32
            | K::MathCos
            | K::MathExp
            | K::MathFloor
            | K::MathFround
            | K::MathHypot
            | K::MathImul
            | K::MathLog
            | K::MathLog10
            | K::MathLog2
            | K::MathMax
            | K::MathMin
            | K::MathPow
            | K::MathRandom
            | K::MathRound
            | K::MathSign
            | K::MathSin
            | K::MathSqrt
            | K::MathTan
            | K::MathTrunc => "Math",
            K::MapClear
            | K::MapDelete
            | K::MapEntries
            | K::MapForEach
            | K::MapGet
            | K::MapHas
            | K::MapKeys
            | K::MapSet
            | K::MapValues => "Map.prototype",
            K::SetAdd
            | K::SetClear
            | K::SetDelete
            | K::SetEntries
            | K::SetForEach
            | K::SetHas
            | K::SetValues => "Set.prototype",
            K::WeakMapMethod => "WeakMap.prototype",
            K::WeakSetMethod => "WeakSet.prototype",
            K::TextCodecMethod => {
                if self.module_specifier.0.as_deref() == Some("decode") {
                    "TextDecoder.prototype"
                } else {
                    "TextEncoder.prototype"
                }
            }
            K::NumberToExponential
            | K::NumberToFixed
            | K::NumberToLocaleString
            | K::NumberToPrecision
            | K::NumberToString
            | K::NumberValueOf => "Number.prototype",
            K::BooleanPrototypeToString | K::BooleanPrototypeValueOf => "Boolean.prototype",
            K::PromiseAll
            | K::PromiseAllSettled
            | K::PromiseAny
            | K::PromiseRace
            | K::PromiseReject
            | K::PromiseResolve
            | K::PromiseWithResolvers => "Promise",
            K::PromiseThen | K::PromiseCatch | K::PromiseFinally => "Promise.prototype",
            K::TypedArrayCopyWithin
            | K::TypedArrayEntries
            | K::TypedArrayFill
            | K::TypedArrayKeys
            | K::TypedArraySet
            | K::TypedArraySlice
            | K::TypedArraySubarray
            | K::TypedArrayValues
            | K::TypedArrayMethod => "TypedArray.prototype",
            K::DataViewGetInt32
            | K::DataViewGetUint32
            | K::DataViewGetUint8
            | K::DataViewSetInt32
            | K::DataViewSetUint32
            | K::DataViewSetUint8
            | K::DataViewMethod => "DataView.prototype",
            K::ObjectHasOwnProperty
            | K::ObjectPrototypeIsPrototypeOf
            | K::ObjectPrototypeToLocaleString
            | K::ObjectPrototypePropertyIsEnumerable
            | K::ObjectPrototypeToString
            | K::ObjectPrototypeValueOf => "Object.prototype",
            K::FunctionPrototypeApply
            | K::FunctionPrototypeBind
            | K::FunctionPrototypeCall
            | K::FunctionPrototypeToString
            | K::FunctionPrototypeHasInstance => "Function.prototype",
            K::RegExpPrototypeExec
            | K::RegExpTest
            | K::RegExpPrototypeToString
            | K::RegExpPrototypeCompile => "RegExp.prototype",
            K::DateNow | K::DateParse | K::DateUtc => "Date",
            K::DateGetTime | K::DatePrototypeMethod | K::DatePrototypeToPrimitive => {
                "Date.prototype"
            }
            K::SymbolPrototypeToString
            | K::SymbolPrototypeValueOf
            | K::SymbolPrototypeToPrimitive => "Symbol.prototype",
            K::BlobMethod => "Blob.prototype",
            K::SharedArrayBufferMethod => "SharedArrayBuffer.prototype",
            K::ArrayBufferMethod => "ArrayBuffer.prototype",
            K::AtomicsMethod => "Atomics",
            K::BigIntAsIntN | K::BigIntAsUintN => "BigInt",
            K::BigIntToString | K::BigIntValueOf => "BigInt.prototype",
            K::ErrorPrototypeToString => "Error.prototype",
            K::ErrorCaptureStackTrace => "Error",
            K::ArrayBufferSlice => "ArrayBuffer.prototype",
            K::WeakRefDeref => "WeakRef.prototype",
            K::FinalizationRegistryMethod => "FinalizationRegistry.prototype",
            K::RegExpSymbolMethod => "RegExp.prototype",
            K::TypedArrayStaticMethod => "TypedArray",
            K::IntlConstructor | K::IntlGetCanonicalLocales => "Intl",
            K::IntlMethod => match self
                .module_specifier
                .0
                .as_deref()
                .and_then(|specifier| specifier.split_once('.'))
                .map(|(service, _)| service)
            {
                Some("NumberFormat") => "Intl.NumberFormat.prototype",
                Some("DateTimeFormat") => "Intl.DateTimeFormat.prototype",
                Some("Collator") => "Intl.Collator.prototype",
                Some("RelativeTimeFormat") => "Intl.RelativeTimeFormat.prototype",
                Some("ListFormat") => "Intl.ListFormat.prototype",
                Some("Segmenter") => "Intl.Segmenter.prototype",
                Some("Segments") => "Intl.Segments",
                _ => "Intl.PluralRules.prototype",
            },
            K::ConsoleLog
            | K::ConsoleError
            | K::ConsoleWarn
            | K::ConsoleInfo
            | K::ConsoleMethod => "console",
            K::UrlMethod => "URL.prototype",
            K::UrlStatic => "URL",
            K::UrlSearchParamsGet
            | K::UrlSearchParamsHas
            | K::UrlSearchParamsGetAll
            | K::UrlSearchParamsAppend
            | K::UrlSearchParamsSort
            | K::UrlSearchParamsDelete
            | K::UrlSearchParamsSet
            | K::UrlSearchParamsToString
            | K::UrlSearchParamsKeys
            | K::UrlSearchParamsValues
            | K::UrlSearchParamsEntries
            | K::UrlSearchParamsForEach => "URLSearchParams.prototype",
            K::EventTargetMethod => event_target::EVENT_TARGET_METHODS
                .iter()
                .find(|(specifier, _, _)| self.module_specifier.0.as_deref() == Some(*specifier))
                .map(|(_, owner, _)| *owner)?,
            K::IteratorHelperMethod => iterator_helpers::ITERATOR_HELPER_METHODS
                .iter()
                .find(|(specifier, _, _)| self.module_specifier.0.as_deref() == Some(*specifier))
                .map(|(_, owner, _)| *owner)?,
            K::StringHtmlMethod => "String.prototype",
            K::ObjectLegacyAccessor => "Object.prototype",
            K::SetMethod => "Set.prototype",
            K::SetTimeout
            | K::SetInterval
            | K::SetImmediate
            | K::ClearTimeout
            | K::ClearInterval
            | K::ClearImmediate
            | K::QueueMicrotask
            | K::StandardConstructor
            | K::FunctionConstructor
            | K::DateConstructor
            | K::PromiseConstructor => "globalThis",
            K::StaticHostcall => static_hostcall_owner_and_name(&self.module_specifier)?.0,
            _ => return None,
        })
    }

    /// bd-9vouw.17: the built-in's own `length` (ES2020 17: the number of
    /// required parameters in its specification). Iterator steps and the
    /// spec's anonymous Promise.prototype.finally closures have fixed
    /// lengths; kinds the engine does not model return `None`.
    fn spec_length(&self) -> Option<i64> {
        use BuiltinFunctionKind as K;
        if self.kind == K::NativeHttpFunction {
            return native_http_function_metadata(&self.module_specifier)
                .map(|(_, _, length)| length);
        }
        if self.kind == K::NativeChildProcessFunction {
            return native_child_process_function_metadata(&self.module_specifier)
                .map(|(_, _, length)| length);
        }
        let fixed = match self.kind {
            K::GeneratorNext
            | K::GeneratorReturn
            | K::GeneratorThrow
            | K::AsyncGeneratorNext
            | K::AsyncGeneratorReturn
            | K::AsyncGeneratorThrow
            | K::PromiseThenFinally
            | K::PromiseCatchFinally
            | K::ArrayFromAsyncFulfilled
            | K::ArrayFromAsyncRejected
            | K::PromiseAllResolveElement
            | K::PromiseAllSettledResolveElement
            | K::PromiseAllSettledRejectElement
            | K::PromiseAnyRejectElement
            | K::ModuleCreateRequire
            | K::ImportMetaResolve
            | K::ObjectProtoSetter => Some(1),
            K::PromiseCapabilityExecutor => Some(2),
            K::IteratorNext
            | K::IteratorSelf
            | K::AsyncGeneratorIteratorSelf
            | K::GeneratorIteratorSelf
            | K::StringIterator
            | K::PromiseFinallyValueThunk
            | K::PromiseFinallyThrower
            | K::ProxyRevoke
            | K::PrototypeGetter
            | K::FunctionPrototype
            | K::NativeTimerPromisesGetter
            | K::ThrowTypeError => Some(0),
            _ => None,
        };
        if fixed.is_some() {
            return fixed;
        }
        let owner = self.spec_owner()?;
        let key = match self.kind {
            K::StandardConstructor => canonical_builtin_prototype_name(&self.module_specifier)?,
            _ => self.display_name(),
        };
        builtin_function_lengths::builtin_function_length(owner, key).map(i64::from)
    }

    /// bd-9vouw.17: the built-in's own `name`: its property key, with
    /// symbol-keyed methods named `[Symbol.iterator]` (ES2020 9.2.13).
    fn spec_name(&self) -> &'static str {
        // A promise's resolving functions (CreateResolvingFunctions, the
        // executor's `resolve`/`reject`) are anonymous built-ins (ES2020
        // 25.6.1.3): only the static Promise.resolve/reject are named.
        if matches!(
            self.kind,
            BuiltinFunctionKind::PromiseResolve | BuiltinFunctionKind::PromiseReject
        ) && self.bound_object.is_some()
        {
            return "";
        }
        match self.display_name() {
            "@@iterator" => "[Symbol.iterator]",
            "@@asyncIterator" => "[Symbol.asyncIterator]",
            name => REGEXP_SYMBOL_METHODS
                .iter()
                .find(|(key, _)| *key == name)
                .map_or(name, |(_, spec_name)| *spec_name),
        }
    }
}

/// %TypedArray% (ES2020 22.2.1): the abstract superclass of the typed array
/// constructors, a standard constructor that is not a global binding.
const TYPED_ARRAY_INTRINSIC: &str = "TypedArray";
/// Module specifier of the %TypedArray%.prototype methods that share an
/// Array.prototype algorithm (`some`, `indexOf`, ...): they are distinct
/// functions whose receiver must be a typed array.
const TYPED_ARRAY_PROTOTYPE_SPECIFIER: &str = "%TypedArray%.prototype";
/// %IteratorPrototype% (ES2020 25.1.2), %ArrayIteratorPrototype% (22.1.5.2),
/// %GeneratorPrototype% (25.4.1) and %AsyncGeneratorPrototype% (ES2018
/// 25.5.1): prototypes no global names, the [[Prototype]] an iterator,
/// generator or async generator value reports. Their names are not
/// identifiers, so no `builtin:proto:` tag can reach them.
const ITERATOR_PROTOTYPE: &str = "%IteratorPrototype%";
const ARRAY_ITERATOR_PROTOTYPE: &str = "%ArrayIteratorPrototype%";
/// %MapIteratorPrototype% and %SetIteratorPrototype% (ES2020 23.1.5.2,
/// 23.2.5.2; bd-9vouw.121): the prototypes of the live Map and Set iterators.
const MAP_ITERATOR_PROTOTYPE: &str = "%MapIteratorPrototype%";
const SET_ITERATOR_PROTOTYPE: &str = "%SetIteratorPrototype%";
const GENERATOR_PROTOTYPE: &str = "%GeneratorPrototype%";
const ASYNC_GENERATOR_PROTOTYPE: &str = "%AsyncGeneratorPrototype%";
/// %AsyncIteratorPrototype% (ES2018 25.1.3): %AsyncGeneratorPrototype%'s
/// [[Prototype]], whose @@asyncIterator returns its receiver.
const ASYNC_ITERATOR_PROTOTYPE: &str = "%AsyncIteratorPrototype%";
/// %GeneratorFunction%, %AsyncFunction% and %AsyncGeneratorFunction% (ES2020
/// 25.2, 25.7; ES2018 25.3): standard constructors that are not global
/// bindings, reached as the `constructor` of their prototypes, which are the
/// [[Prototype]] of generator, async and async generator functions.
const FUNCTION_KIND_INTRINSICS: [&str; 3] = [
    "GeneratorFunction",
    "AsyncFunction",
    "AsyncGeneratorFunction",
];

/// The name of the wrapper a generator or async dynamic function is
/// compiled inside; NUL-free but not a name source text can collide with in
/// the one-statement wrapper it heads.
const DYNAMIC_FUNCTION_WRAPPER: &str = "__franken_dynamic_function";

/// The kind of function CreateDynamicFunction builds (ES2020 19.2.1.1.1):
/// the Function constructor's, or %GeneratorFunction%'s, %AsyncFunction%'s
/// or %AsyncGeneratorFunction%'s (bd-9vouw.321).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DynamicFunctionKind {
    Normal,
    Generator,
    Async,
    AsyncGenerator,
}

impl DynamicFunctionKind {
    fn for_constructor(name: &str) -> Option<Self> {
        match name {
            "GeneratorFunction" => Some(Self::Generator),
            "AsyncFunction" => Some(Self::Async),
            "AsyncGeneratorFunction" => Some(Self::AsyncGenerator),
            _ => None,
        }
    }

    fn constructor_name(self) -> &'static str {
        match self {
            Self::Normal => "Function",
            Self::Generator => "GeneratorFunction",
            Self::Async => "AsyncFunction",
            Self::AsyncGenerator => "AsyncGeneratorFunction",
        }
    }

    fn is_async(self) -> bool {
        matches!(self, Self::Async | Self::AsyncGenerator)
    }

    fn is_generator(self) -> bool {
        matches!(self, Self::Generator | Self::AsyncGenerator)
    }

    fn function_keyword(self) -> &'static str {
        match self {
            Self::Normal => "function",
            Self::Generator => "function*",
            Self::Async => "async function",
            Self::AsyncGenerator => "async function*",
        }
    }

    /// The source of the wrapper whose one statement returns the function.
    fn wrapper_source(self, parameters: &str, body: &str) -> String {
        let prefix = self.function_keyword();
        format!(
            "function {DYNAMIC_FUNCTION_WRAPPER}() {{\nreturn {prefix} anonymous({parameters}\n) {{\n{body}\n}};\n}}"
        )
    }

    /// The parameters alone, as a declaration with an empty body: they
    /// must parse as that one declaration, as CreateDynamicFunction parses
    /// them as FormalParameters before forming the full source text (ES2020
    /// 19.2.1.1.1 step 10). Parameter text that opens a comment or closes
    /// the list early is a SyntaxError even when the body would complete it.
    fn parameters_source(self, parameters: &str) -> String {
        format!("{} anonymous({parameters}\n) {{}}", self.function_keyword())
    }

    /// Whether `tree` is exactly one declaration of `anonymous` of this
    /// kind.
    fn is_single_declaration(self, tree: &crate::ast::SyntaxTree) -> bool {
        use crate::ast::Statement;
        matches!(
            tree.body.as_slice(),
            [Statement::FunctionDeclaration(function)]
                if function.name.as_deref() == Some("anonymous")
                    && function.is_async == self.is_async()
                    && function.is_generator == self.is_generator()
        )
    }

    /// Bytes the wrapper adds to the generated source, for the scratch
    /// charge taken before any source is built.
    fn wrapper_overhead_bytes(self) -> u64 {
        match self {
            Self::Normal => 0,
            _ => self.wrapper_source("", "").len() as u64,
        }
    }

    /// Whether `tree` is exactly the wrapper: one declaration of
    /// [`DYNAMIC_FUNCTION_WRAPPER`] whose body is one `return` of a function
    /// named `anonymous` of this kind. Anything else means the parameters
    /// or body closed the inner function early, which CreateDynamicFunction
    /// parses as separate productions and rejects as a SyntaxError.
    fn is_exact_wrapper(self, tree: &crate::ast::SyntaxTree) -> bool {
        use crate::ast::{Expression, ReturnStatement, Statement};
        let [Statement::FunctionDeclaration(wrapper)] = tree.body.as_slice() else {
            return false;
        };
        if wrapper.name.as_deref() != Some(DYNAMIC_FUNCTION_WRAPPER)
            || !wrapper.params.is_empty()
            || wrapper.is_async
            || wrapper.is_generator
        {
            return false;
        }
        let [
            Statement::Return(ReturnStatement {
                argument:
                    Some(Expression::Function {
                        name,
                        is_async,
                        is_generator,
                        ..
                    }),
                ..
            }),
        ] = wrapper.body.body.as_slice()
        else {
            return false;
        };
        name.as_deref() == Some("anonymous")
            && *is_async == self.is_async()
            && *is_generator == self.is_generator()
    }
}

/// bd-9vouw.17: standard constructors bound as first-class global values.
/// Every name has a canonical builtin prototype (`ensure_builtin_prototype`),
/// which is also the prototype engine-created instances use, so `instanceof`,
/// `x.constructor === X` and `class E extends X` agree with the instances.
pub(crate) const STANDARD_CONSTRUCTOR_GLOBALS: [&str; 50] = [
    "Object",
    "Array",
    "Number",
    "String",
    "Boolean",
    "BigInt",
    "Map",
    "Set",
    "Error",
    "TypeError",
    "RangeError",
    "ReferenceError",
    "SyntaxError",
    "EvalError",
    "URIError",
    "AggregateError",
    "RegExp",
    "WeakMap",
    "WeakSet",
    // ES2021: `new WeakRef(t)` / `new FinalizationRegistry(f)` stay
    // intercepted at lowering; called without `new` they throw.
    "WeakRef",
    "FinalizationRegistry",
    // Binary data constructors: direct `new Uint8Array(...)` stays intercepted
    // at lowering; these bindings make the constructors usable as values
    // (Test262's testTypedArray.js lists all nine at load).
    "ArrayBuffer",
    "DataView",
    "Int8Array",
    "Uint8Array",
    "Uint8ClampedArray",
    "Int16Array",
    "Uint16Array",
    "Int32Array",
    "Uint32Array",
    "Float32Array",
    "Float64Array",
    "BigInt64Array",
    "BigUint64Array",
    // `new Proxy(t, h)` stays intercepted at lowering; the binding makes
    // `typeof Proxy` "function" (library feature detection) and the
    // constructor usable as a value. Proxy has no `prototype`.
    "Proxy",
    // `Symbol(d)`, `Symbol.for` and `Symbol.iterator` stay intercepted at
    // lowering; the binding makes `Symbol` a value (`var S = Symbol`,
    // `root.Symbol`-style aliases). Not constructible.
    "Symbol",
    // WHATWG Encoding (bd-3l74k): pure builtins, no authority.
    "TextEncoder",
    "TextDecoder",
    // Node's Buffer (bd-9vouw.104): a pure-compute Uint8Array subclass. Its
    // statics are the slot-0 builtins lowering also calls directly.
    "Buffer",
    // WHATWG URL (bd-9vouw.157): constructing through the value builds the
    // same engine-owned objects as `new URL(...)`.
    "URL",
    "URLSearchParams",
    // WHATWG DOM events and aborting (bd-9vouw.170): Node globals.
    "EventTarget",
    "Event",
    "CustomEvent",
    "AbortController",
    "AbortSignal",
    "DOMException",
    // WHATWG File API Blob (bd-9vouw.226): a Node global since v18.
    "Blob",
    // ES2020 24.2 (bd-9vouw.244).
    "SharedArrayBuffer",
    // ES2025 Iterator (bd-9vouw.179): abstract; its prototype is
    // %IteratorPrototype%, which holds the helpers.
    "Iterator",
];

/// bd-9vouw.17: realm globals besides the standard constructors and global
/// functions that the global object carries. `process` is deliberately
/// absent: it is a host-authority surface reachable only through its gated
/// identifier.
const GLOBAL_OBJECT_MEMBERS: [&str; 17] = [
    "console",
    "performance",
    "Promise",
    "Math",
    "Date",
    "Function",
    "JSON",
    "Reflect",
    "Atomics",
    "Symbol",
    "setTimeout",
    "clearTimeout",
    "setInterval",
    "clearInterval",
    "setImmediate",
    "clearImmediate",
    "queueMicrotask",
];

/// bd-9vouw.17: bare global functions bound as first-class values (the same
/// list the lowering declares factory hostcalls for).
const GLOBAL_FUNCTION_VALUES: [&str; 13] = crate::lowering_pipeline::GLOBAL_FUNCTION_VALUE_NAMES;

/// The RegExp flags in the order the `flags` getter lists them (ES2025
/// 22.2.6.4): hasIndices, global, ignoreCase, multiline, dotAll, unicode,
/// unicodeSets, sticky.
const REGEXP_FLAG_ORDER: &str = "dgimsuvy";

/// The generated Function realm's bindings to objects of its own
/// (bd-fw7zd.8.3, bd-9vouw.133): its console, performance, Math, JSON,
/// Reflect and Atomics (bd-9vouw.245), and its global object under both
/// names. The registry's memory projection counts these.
const GENERATED_REALM_OBJECT_GLOBALS: [&str; 8] = [
    "console",
    "performance",
    "Math",
    "JSON",
    "Reflect",
    "Atomics",
    "globalThis",
    "global",
];

/// Realm-owned provider objects, shared by bare and node-prefixed loads.
const CRYPTO_MODULE_KEY: &str = "<module crypto>";
const ZLIB_MODULE_KEY: &str = "<module zlib>";
const HTTP_MODULE_KEY: &str = "<module http>";
const HTTPS_MODULE_KEY: &str = "<module https>";
const CHILD_PROCESS_MODULE_KEY: &str = "<module child_process>";

/// The private discriminators are the existing process_spawn wire format.
/// Keeping them on engine-created values never grants process authority.
const CHILD_PROCESS_FUNCTIONS: [(&str, &str, i64); 6] = [
    ("\0processop:spawn", "spawn", 3),
    ("\0processop:spawn_sync", "spawnSync", 3),
    ("\0processop:exec", "exec", 3),
    ("\0processop:exec_sync", "execSync", 2),
    ("\0processop:exec_file", "execFile", 4),
    ("\0processop:exec_file_sync", "execFileSync", 3),
];

fn native_child_process_function_metadata(
    operation: &str,
) -> Option<(&'static str, &'static str, i64)> {
    CHILD_PROCESS_FUNCTIONS
        .iter()
        .copied()
        .find(|(candidate, _, _)| *candidate == operation)
}

/// Exact finite provider surface. These are the same operations as direct
/// HTTP lowering, including the separate TLS request path.
fn native_http_function_metadata(tag: &str) -> Option<(&'static str, &'static str, i64)> {
    Some(match tag {
        "builtin:HttpCreateServer" => ("builtin:HttpCreateServer", "createServer", 2),
        "builtin:HttpGet" => ("builtin:HttpGet", "get", 3),
        "builtin:HttpRequest" => ("builtin:HttpRequest", "request", 3),
        "builtin:HttpAgent" => ("builtin:HttpAgent", "Agent", 1),
        "builtin:HttpsGet" => ("builtin:HttpsGet", "get", 3),
        "builtin:HttpsRequest" => ("builtin:HttpsRequest", "request", 0),
        "builtin:HttpsAgent" => ("builtin:HttpsAgent", "Agent", 1),
        _ => return None,
    })
}

/// Retained native `module` provider shared by bare and `node:` aliases.
const MODULE_MODULE_KEY: &str = "<module module>";

/// Seed-tracked slot of the `require('os')` module object (bd-9vouw.204).
const OS_MODULE_KEY: &str = "<module os>";

/// Seed-tracked slot of the realm's querystring module (bd-305gi), shared by
/// the lowering factory and runtime CommonJS requests.
const QUERYSTRING_MODULE_KEY: &str = "<module querystring>";

/// Runtime-loaded path namespaces share one retained engine-owned factory.
const PATH_MODULE_KEY: &str = "<module path>";
const PATH_WIN32_MODULE_KEY: &str = "<module path/win32>";
const PATH_RUNTIME_MODULE_ID: &str = "\0franken-engine/native-path";
const PATH_ESM_MODULE_ID: &str = "\0franken-engine/native-path/esm";
const PATH_POSIX_ESM_MODULE_ID: &str = "\0franken-engine/native-path/posix/esm";
const PATH_WIN32_ESM_MODULE_ID: &str = "\0franken-engine/native-path/win32/esm";
// The supported native Path surface, in Node's export-read order. ESM
// snapshots this fixed list on its first load; guest-added properties are
// not exports, while deleted original properties still export undefined.
const PATH_ESM_EXPORT_NAMES: [&str; 15] = [
    "resolve",
    "normalize",
    "isAbsolute",
    "join",
    "relative",
    "toNamespacedPath",
    "dirname",
    "basename",
    "extname",
    "format",
    "parse",
    "sep",
    "delimiter",
    "win32",
    "posix",
];

/// Seed-tracked slot of the `require('url')` module object (bd-9vouw.224).
const URL_MODULE_KEY: &str = "<module url>";

/// Seed-tracked slot of the `require('timers')` module object (bd-9vouw.231).
const TIMERS_MODULE_KEY: &str = "<module timers>";

/// Seed-tracked slot of the `require('perf_hooks')` module object
/// (bd-9vouw.302).
const PERF_HOOKS_MODULE_KEY: &str = "<module perf_hooks>";

/// EventEmitter.prototype's methods, own enumerable properties in Node v22's
/// order (bd-9vouw.210).
const EVENT_EMITTER_PROTOTYPE_METHODS: [&str; 15] = [
    "setMaxListeners",
    "getMaxListeners",
    "emit",
    "addListener",
    "on",
    "prependListener",
    "once",
    "prependOnceListener",
    "removeListener",
    "off",
    "removeAllListeners",
    "listeners",
    "rawListeners",
    "listenerCount",
    "eventNames",
];

/// The names Array.prototype[@@unscopables] blocks in a `with` body, as Node
/// v22 lists them (ES2020 22.1.3.32 plus later additions).
/// %Array.prototype%'s own string keys in Node v22's order (bd-9vouw.122).
const ARRAY_PROTOTYPE_OWN_NAMES: [&str; 40] = [
    "length",
    "constructor",
    "at",
    "concat",
    "copyWithin",
    "fill",
    "find",
    "findIndex",
    "findLast",
    "findLastIndex",
    "lastIndexOf",
    "pop",
    "push",
    "reverse",
    "shift",
    "unshift",
    "slice",
    "sort",
    "splice",
    "includes",
    "indexOf",
    "join",
    "keys",
    "entries",
    "values",
    "forEach",
    "filter",
    "flat",
    "flatMap",
    "map",
    "every",
    "some",
    "reduce",
    "reduceRight",
    "toReversed",
    "toSorted",
    "toSpliced",
    "with",
    "toLocaleString",
    "toString",
];

const ARRAY_UNSCOPABLE_NAMES: [&str; 16] = [
    "at",
    "copyWithin",
    "entries",
    "fill",
    "find",
    "findIndex",
    "findLast",
    "findLastIndex",
    "flat",
    "flatMap",
    "includes",
    "keys",
    "toReversed",
    "toSorted",
    "toSpliced",
    "values",
];

/// Canonical prototypes (`builtin_prototypes` keys) whose methods are served
/// virtually by [`InterpreterCore::canonical_prototype_method`] instead of
/// being stored as own heap properties (bd-9vouw.17).
const VIRTUAL_METHOD_PROTOTYPES: [&str; 30] = [
    "Array",
    "String",
    "Number",
    "Boolean",
    "BigInt",
    "Symbol",
    "Map",
    "Set",
    "Function",
    "Date",
    "RegExp",
    "Promise",
    "WeakMap",
    "WeakSet",
    "DataView",
    "ArrayBuffer",
    "WeakRef",
    "FinalizationRegistry",
    "TypedArray",
    "TextEncoder",
    "TextDecoder",
    "Buffer",
    "URL",
    "URLSearchParams",
    "EventTarget",
    "Event",
    "AbortController",
    "AbortSignal",
    "Blob",
    "SharedArrayBuffer",
];

/// `console` methods besides log/error/warn/info (bd-9vouw.158), as Node
/// v22.2.0 has them.
const CONSOLE_EXTRA_METHODS: [&str; 15] = [
    "debug",
    "trace",
    "dir",
    "dirxml",
    "time",
    "timeEnd",
    "timeLog",
    "count",
    "countReset",
    "group",
    "groupCollapsed",
    "groupEnd",
    "assert",
    "clear",
    "table",
];

/// A console.table: its header row and its columns, each a cell per row
/// (`None` where an item has no such property), bd-9vouw.158.
type ConsoleTableColumns = (Vec<String>, Vec<Vec<Option<String>>>);

/// Node's `console.time` rendering of an elapsed time in milliseconds
/// (lib/internal/console/constructor.js formatTime), bd-9vouw.158.
fn console_elapsed_time(elapsed_ms: f64) -> String {
    const SECOND: f64 = 1000.0;
    const MINUTE: f64 = 60.0 * SECOND;
    const HOUR: f64 = 60.0 * MINUTE;
    let (mut hours, mut minutes, mut seconds, mut ms) = (0.0, 0.0, 0.0, elapsed_ms);
    if ms >= SECOND {
        if ms >= MINUTE {
            if ms >= HOUR {
                hours = (ms / HOUR).floor();
                ms %= HOUR;
            }
            minutes = (ms / MINUTE).floor();
            ms %= MINUTE;
        }
        seconds = ms / SECOND;
    }
    if hours != 0.0 || minutes != 0.0 {
        let fixed = format!("{seconds:.3}");
        let (whole, fraction) = fixed.split_once('.').unwrap_or((fixed.as_str(), "000"));
        let head = if hours != 0.0 {
            format!("{hours}:{minutes:0>2}")
        } else {
            format!("{minutes}")
        };
        let unit = if hours != 0.0 { "h:m" } else { "" };
        return format!("{head}:{whole:0>2}.{fraction} ({unit}m:ss.mmm)");
    }
    if seconds != 0.0 {
        return format!("{seconds:.3}s");
    }
    // Number(ms.toFixed(3)): trailing zeros dropped.
    let rounded = (ms * 1000.0).round() / 1000.0;
    format!("{}ms", ryu_js::Buffer::new().format(rounded))
}

/// `Date.prototype` methods served by [`BuiltinFunctionKind::DatePrototypeMethod`].
/// FrankenEngine is hermetic: local time is UTC, so each local accessor
/// equals its `UTC` twin and `getTimezoneOffset()` is 0.
const DATE_PROTOTYPE_METHODS: [&str; 45] = [
    "valueOf",
    "getFullYear",
    "getUTCFullYear",
    "getMonth",
    "getUTCMonth",
    "getDate",
    "getUTCDate",
    "getDay",
    "getUTCDay",
    "getHours",
    "getUTCHours",
    "getMinutes",
    "getUTCMinutes",
    "getSeconds",
    "getUTCSeconds",
    "getMilliseconds",
    "getUTCMilliseconds",
    "getTimezoneOffset",
    "toISOString",
    "toJSON",
    "setTime",
    "setMilliseconds",
    "setUTCMilliseconds",
    "setSeconds",
    "setUTCSeconds",
    "setMinutes",
    "setUTCMinutes",
    "setHours",
    "setUTCHours",
    "setDate",
    "setUTCDate",
    "setMonth",
    "setUTCMonth",
    "setFullYear",
    "setUTCFullYear",
    "toUTCString",
    "toGMTString",
    "toString",
    "toDateString",
    "toTimeString",
    "toLocaleString",
    "toLocaleDateString",
    "toLocaleTimeString",
    // Annex B B.2.4 (bd-9vouw.240).
    "getYear",
    "setYear",
];

/// ES2020 20.4.1 time-value arithmetic on milliseconds since the epoch (UTC).
mod date_math {
    pub(super) const MS_PER_DAY: f64 = 86_400_000.0;

    pub(super) fn day(t: f64) -> f64 {
        (t / MS_PER_DAY).floor()
    }

    fn days_in_year(y: f64) -> f64 {
        if y % 4.0 != 0.0 {
            365.0
        } else if y % 100.0 != 0.0 {
            366.0
        } else if y % 400.0 != 0.0 {
            365.0
        } else {
            366.0
        }
    }

    fn day_from_year(y: f64) -> f64 {
        365.0 * (y - 1970.0) + ((y - 1969.0) / 4.0).floor() - ((y - 1901.0) / 100.0).floor()
            + ((y - 1601.0) / 400.0).floor()
    }

    fn time_from_year(y: f64) -> f64 {
        MS_PER_DAY * day_from_year(y)
    }

    pub(super) fn year_from_time(t: f64) -> f64 {
        let mut y = (t / (365.2425 * MS_PER_DAY)).floor() + 1970.0;
        while time_from_year(y) > t {
            y -= 1.0;
        }
        while time_from_year(y + 1.0) <= t {
            y += 1.0;
        }
        y
    }

    fn cumulative_days(month: usize, leap: bool) -> f64 {
        const DAYS: [f64; 12] = [
            0.0, 31.0, 59.0, 90.0, 120.0, 151.0, 181.0, 212.0, 243.0, 273.0, 304.0, 334.0,
        ];
        DAYS[month] + if leap && month >= 2 { 1.0 } else { 0.0 }
    }

    pub(super) fn month_from_time(t: f64) -> f64 {
        let year = year_from_time(t);
        let leap = days_in_year(year) == 366.0;
        let within = day(t) - day_from_year(year);
        (1..12)
            .rev()
            .find(|month| within >= cumulative_days(*month, leap))
            .unwrap_or(0) as f64
    }

    pub(super) fn date_from_time(t: f64) -> f64 {
        let year = year_from_time(t);
        let leap = days_in_year(year) == 366.0;
        let within = day(t) - day_from_year(year);
        within - cumulative_days(month_from_time(t) as usize, leap) + 1.0
    }

    pub(super) fn week_day(t: f64) -> f64 {
        (day(t) + 4.0).rem_euclid(7.0)
    }

    pub(super) fn hour(t: f64) -> f64 {
        (t / 3_600_000.0).floor().rem_euclid(24.0)
    }

    pub(super) fn minute(t: f64) -> f64 {
        (t / 60_000.0).floor().rem_euclid(60.0)
    }

    pub(super) fn second(t: f64) -> f64 {
        (t / 1000.0).floor().rem_euclid(60.0)
    }

    pub(super) fn millisecond(t: f64) -> f64 {
        t.rem_euclid(1000.0)
    }

    fn to_integer(value: f64) -> f64 {
        if value.is_nan() { 0.0 } else { value.trunc() }
    }

    /// MakeTime (20.4.1.11).
    pub(super) fn make_time(hour: f64, min: f64, sec: f64, ms: f64) -> f64 {
        if ![hour, min, sec, ms].iter().all(|part| part.is_finite()) {
            return f64::NAN;
        }
        to_integer(hour) * 3_600_000.0
            + to_integer(min) * 60_000.0
            + to_integer(sec) * 1000.0
            + to_integer(ms)
    }

    /// MakeDay (20.4.1.12).
    pub(super) fn make_day(year: f64, month: f64, date: f64) -> f64 {
        if ![year, month, date].iter().all(|part| part.is_finite()) {
            return f64::NAN;
        }
        let (y, m, dt) = (to_integer(year), to_integer(month), to_integer(date));
        let ym = y + (m / 12.0).floor();
        let mn = m.rem_euclid(12.0) as usize;
        let leap = days_in_year(ym) == 366.0;
        day_from_year(ym) + cumulative_days(mn, leap) + dt - 1.0
    }

    /// MakeDate (20.4.1.13).
    pub(super) fn make_date(day: f64, time: f64) -> f64 {
        if !day.is_finite() || !time.is_finite() {
            return f64::NAN;
        }
        day * MS_PER_DAY + time
    }

    /// TimeClip (20.4.1.14).
    pub(super) fn time_clip(time: f64) -> f64 {
        if !time.is_finite() || time.abs() > 8.64e15 {
            f64::NAN
        } else {
            time.trunc() + 0.0
        }
    }

    pub(super) const WEEK_DAY_NAMES: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    pub(super) const MONTH_NAMES: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    /// DateString (20.4.4.41.2): `Www Mmm DD YYYY`, a negative year signed
    /// and every year padded to four digits.
    pub(super) fn date_string(t: f64) -> String {
        let year = year_from_time(t) as i64;
        format!(
            "{} {} {:02} {}{:04}",
            WEEK_DAY_NAMES[week_day(t) as usize],
            MONTH_NAMES[month_from_time(t) as usize],
            date_from_time(t) as i64,
            if year < 0 { "-" } else { "" },
            year.unsigned_abs()
        )
    }

    /// TimeString + TimeZoneString (20.4.4.41.1, 20.4.4.41.3) for the
    /// hermetic UTC local zone: `HH:MM:SS GMT+0000 (Coordinated Universal
    /// Time)`, which is Node's rendering under `TZ=UTC`.
    pub(super) fn time_zone_string(t: f64) -> String {
        format!(
            "{:02}:{:02}:{:02} GMT+0000 (Coordinated Universal Time)",
            hour(t) as i64,
            minute(t) as i64,
            second(t) as i64
        )
    }

    /// ToDateString (20.4.4.41.4): what `Date.prototype.toString` and every
    /// string conversion of a Date produce.
    pub(super) fn to_date_string(t: f64) -> String {
        if t.is_nan() {
            return "Invalid Date".to_string();
        }
        format!("{} {}", date_string(t), time_zone_string(t))
    }
}

fn static_hostcall_name(tag: &str) -> Option<&'static str> {
    static_hostcall_owner_and_name(tag).map(|(_, name)| name)
}

/// Owner (`"Object"`, `"globalThis"`, `"Reflect"`, ...) and member name of a
/// first-class static builtin tag.
fn static_hostcall_owner_and_name(tag: &str) -> Option<(&'static str, &'static str)> {
    slot0_static_owner_and_member(tag)
        .or_else(|| {
            GLOBAL_FUNCTION_VALUES
                .iter()
                .copied()
                .find(|name| {
                    crate::lowering_pipeline::global_function_capability(name) == Some(tag)
                })
                .map(|name| ("globalThis", name))
        })
        .or_else(|| {
            REFLECT_MEMBERS
                .iter()
                .copied()
                .find(|member| {
                    crate::lowering_pipeline::reflect_member_capability(member) == Some(tag)
                })
                .map(|member| ("Reflect", member))
        })
        .or_else(|| {
            crate::lowering_pipeline::OBJECT_RECEIVER_STATIC_MEMBERS
                .iter()
                .copied()
                .find(|member| {
                    crate::lowering_pipeline::object_receiver_static_member_capability(member)
                        == Some(tag)
                })
                .map(|member| ("Object", member))
        })
        // `process.nextTick` read as a value (bd-9vouw.186).
        .or_else(|| (tag == "builtin:ProcessNextTick").then_some(("process", "nextTick")))
        // `eval` read as a value (bd-9vouw.191).
        .or_else(|| (tag == "builtin:Eval").then_some(("globalThis", "eval")))
        // `require('events').once` (bd-9vouw.210).
        .or_else(|| (tag == "builtin:EventsOnce").then_some(("events", "once")))
        // querystring's native methods, including the parse/decode and
        // stringify/encode identity aliases (bd-305gi).
        .or_else(|| {
            crate::lowering_pipeline::QUERYSTRING_METHOD_NAMES
                .iter()
                .copied()
                .find(|name| {
                    crate::lowering_pipeline::querystring_method_capability(name) == Some(tag)
                })
                .map(|name| {
                    let name = match name {
                        "escape" => "qsEscape",
                        "unescape" => "qsUnescape",
                        name => name,
                    };
                    ("querystring", name)
                })
        })
        // The legacy members of `require('url')` (bd-9vouw.224).
        .or(match tag {
            "builtin:UrlFileUrlToPath" => Some(("url", "fileURLToPath")),
            "builtin:UrlFormat" => Some(("url", "format")),
            "builtin:UrlParse" => Some(("url", "parse")),
            _ => None,
        })
        // The members of `require('os')` (bd-9vouw.204).
        .or_else(|| {
            crate::lowering_pipeline::OS_METHOD_NAMES
                .iter()
                .copied()
                .find(|name| crate::lowering_pipeline::os_method_capability(name) == Some(tag))
                .map(|name| ("os", name))
        })
        // The members of `require('querystring')` (bd-9vouw.439): `parse`
        // and `stringify` before their `decode`/`encode` aliases.
        .or_else(|| {
            crate::lowering_pipeline::QUERYSTRING_METHOD_NAMES
                .iter()
                .copied()
                .find(|name| {
                    crate::lowering_pipeline::querystring_method_capability(name) == Some(tag)
                })
                .map(|name| ("querystring", name))
        })
        .or_else(|| {
            crate::lowering_pipeline::CRYPTO_METHOD_NAMES
                .iter()
                .copied()
                .find(|name| crate::lowering_pipeline::crypto_method_capability(name) == Some(tag))
                .map(|name| ("crypto", name))
        })
        .or_else(|| {
            crate::lowering_pipeline::ZLIB_METHOD_NAMES
                .iter()
                .copied()
                .find(|name| crate::lowering_pipeline::zlib_method_capability(name) == Some(tag))
                .map(|name| ("zlib", name))
        })
}

/// `Reflect` members installed on the first-class `Reflect` object; each is
/// the hostcall the lowering routes a direct `Reflect.<member>(...)` call to.
const REFLECT_MEMBERS: [&str; 13] = [
    "apply",
    "construct",
    "defineProperty",
    "deleteProperty",
    "get",
    "getOwnPropertyDescriptor",
    "getPrototypeOf",
    "has",
    "isExtensible",
    "ownKeys",
    "preventExtensions",
    "set",
    "setPrototypeOf",
];

/// The `'static` spelling of a first-class static builtin tag, or `None` if
/// the shared lowering tables cannot produce it.
fn canonical_static_hostcall_tag(tag: &str) -> Option<&'static str> {
    SLOT0_STATIC_GLOBALS
        .iter()
        .flat_map(|global| {
            SLOT0_STATIC_MEMBERS.iter().filter_map(move |member| {
                crate::lowering_pipeline::slot0_static_member_capability(global, member)
            })
        })
        .chain(
            GLOBAL_FUNCTION_VALUES
                .iter()
                .filter_map(|name| crate::lowering_pipeline::global_function_capability(name)),
        )
        .chain(
            REFLECT_MEMBERS
                .iter()
                .filter_map(|member| crate::lowering_pipeline::reflect_member_capability(member)),
        )
        .chain(
            crate::lowering_pipeline::OBJECT_RECEIVER_STATIC_MEMBERS
                .iter()
                .filter_map(|member| {
                    crate::lowering_pipeline::object_receiver_static_member_capability(member)
                }),
        )
        // `process.nextTick` read as a value (bd-9vouw.186).
        .chain(std::iter::once("builtin:ProcessNextTick"))
        // `eval` read as a value (bd-9vouw.191).
        .chain(std::iter::once("builtin:Eval"))
        .find(|candidate| *candidate == tag)
}

/// Where a collection constructor reads its seed values from.
enum CollectionSeedSource {
    /// Values read without an observable iterator (an ordinary array, or
    /// no iterable at all).
    Values(std::vec::IntoIter<Value>),
    /// A for-of iterator over any other iterable.
    Iterator(Value),
}

/// A typed array's heap entries that are not own properties in ES2020
/// (prototype accessors and engine slots); see own_property_visible.
const TYPED_ARRAY_SLOT_KEYS: [&str; 6] = [
    "__typedArrayKind",
    "length",
    "byteLength",
    "byteOffset",
    "buffer",
    "BYTES_PER_ELEMENT",
];

/// The heap entries of an ArrayBuffer and a DataView that model internal
/// slots and prototype accessors, not own properties (see
/// `own_property_visible`).
const ARRAY_BUFFER_SLOT_KEYS: [&str; 1] = ["byteLength"];
const DATA_VIEW_SLOT_KEYS: [&str; 3] = ["buffer", "byteLength", "byteOffset"];

const SLOT0_STATIC_GLOBALS: [&str; 10] = [
    "Object",
    "JSON",
    "Array",
    "String",
    "Symbol",
    "Proxy",
    "Map",
    "ArrayBuffer",
    "Number",
    "Buffer",
];
const SLOT0_STATIC_MEMBERS: [&str; 46] = [
    "keys",
    "hasOwn",
    "values",
    "entries",
    "assign",
    "freeze",
    "isFrozen",
    "create",
    "getPrototypeOf",
    "setPrototypeOf",
    "defineProperty",
    "defineProperties",
    "getOwnPropertyNames",
    "getOwnPropertySymbols",
    "getOwnPropertyDescriptor",
    "getOwnPropertyDescriptors",
    "fromEntries",
    "groupBy",
    "isView",
    "parse",
    "stringify",
    "rawJSON",
    "isRawJSON",
    "isArray",
    "from",
    "fromAsync",
    "of",
    "fromCharCode",
    "fromCodePoint",
    "raw",
    "for",
    "keyFor",
    "revocable",
    "isInteger",
    "isSafeInteger",
    "isFinite",
    "isNaN",
    "parseInt",
    "parseFloat",
    "alloc",
    "allocUnsafe",
    "byteLength",
    "concat",
    "compare",
    "isBuffer",
    "isEncoding",
];

/// Owner global and member name for a slot-0 static hostcall tag, for
/// `Function.prototype.name` style display and `length` lookup. Only tags the
/// shared lowering table can produce resolve.
fn slot0_static_owner_and_member(tag: &str) -> Option<(&'static str, &'static str)> {
    SLOT0_STATIC_GLOBALS.iter().copied().find_map(|global| {
        SLOT0_STATIC_MEMBERS
            .iter()
            .copied()
            .find(|member| {
                crate::lowering_pipeline::slot0_static_member_capability(global, member)
                    == Some(tag)
            })
            .map(|member| (global, member))
    })
}

impl Value {
    pub fn str(value: impl Into<JsString>) -> Self {
        Self::Str(value.into())
    }

    /// Truthiness: Undefined, Null, Bool(false), Int(0), Float(0.0/-0.0/NaN), Str("") are falsy.
    pub fn is_truthy(&self) -> bool {
        match self {
            Self::Undefined | Self::Null => false,
            Self::Bool(b) => *b,
            Self::Int(n) => *n != 0,
            Self::BigInt(n) => n.as_ref() != "0",
            Self::Float(f) => !f.is_nan() && f.inner() != 0.0,
            Self::Str(s) => !s.is_empty(),
            Self::Symbol(_) => true,
            Self::Object(_)
            | Self::Function(_)
            | Self::Closure(_)
            | Self::Iterator(_)
            | Self::GeneratorFunction(_)
            | Self::Generator(_)
            | Self::AsyncFunction(_)
            | Self::AsyncFunctionObject(_)
            | Self::AsyncGeneratorFunction(_)
            | Self::AsyncGeneratorObject(_)
            | Self::Promise(_)
            | Self::BuiltinFunction(_)
            | Self::Accessor { .. } => true,
        }
    }

    pub fn is_nullish(&self) -> bool {
        matches!(self, Self::Undefined | Self::Null)
    }

    /// Whether this runtime value has ECMAScript object identity.
    ///
    /// Functions, promises, iterators, and other exotic objects use dedicated
    /// carrier variants rather than [`Value::Object`]. Keep this match
    /// exhaustive so every future variant makes an explicit
    /// object-versus-primitive choice (bd-ptu9m).
    #[allow(clippy::match_like_matches_macro)] // Exhaustiveness is the point of this classifier.
    pub fn is_object_like(&self) -> bool {
        match self {
            Self::Undefined
            | Self::Null
            | Self::Bool(_)
            | Self::Int(_)
            | Self::BigInt(_)
            | Self::Float(_)
            | Self::Str(_)
            | Self::Symbol(_) => false,
            Self::Object(_)
            | Self::Function(_)
            | Self::Closure(_)
            | Self::Iterator(_)
            | Self::GeneratorFunction(_)
            | Self::Generator(_)
            | Self::AsyncFunction(_)
            | Self::AsyncFunctionObject(_)
            | Self::AsyncGeneratorFunction(_)
            | Self::AsyncGeneratorObject(_)
            | Self::Promise(_)
            | Self::BuiltinFunction(_)
            | Self::Accessor { .. } => true,
        }
    }

    pub fn is_callable(&self) -> bool {
        matches!(
            self,
            Self::Function(_)
                | Self::Closure(_)
                | Self::GeneratorFunction(_)
                | Self::AsyncFunction(_)
                | Self::AsyncGeneratorFunction(_)
                | Self::BuiltinFunction(_)
        )
    }

    /// Type name for error messages.
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Undefined => "undefined",
            Self::Null => "null",
            Self::Bool(_) => "boolean",
            Self::Int(_) | Self::Float(_) => "number",
            Self::BigInt(_) => "bigint",
            Self::Str(_) => "string",
            Self::Symbol(_) => "symbol",
            Self::Object(_) => "object",
            Self::Function(_)
            | Self::Closure(_)
            | Self::GeneratorFunction(_)
            | Self::AsyncFunction(_)
            | Self::AsyncGeneratorFunction(_)
            | Self::BuiltinFunction(_) => "function",
            Self::Iterator(_)
            | Self::Generator(_)
            | Self::AsyncFunctionObject(_)
            | Self::AsyncGeneratorObject(_)
            | Self::Promise(_)
            | Self::Accessor { .. } => "object",
        }
    }

    pub fn typeof_name(&self) -> &'static str {
        match self {
            Self::Undefined => "undefined",
            Self::Null | Self::Object(_) => "object",
            Self::Bool(_) => "boolean",
            Self::Int(_) | Self::Float(_) => "number",
            Self::BigInt(_) => "bigint",
            Self::Str(_) => "string",
            Self::Symbol(_) => "symbol",
            Self::Function(_)
            | Self::Closure(_)
            | Self::GeneratorFunction(_)
            | Self::AsyncFunction(_)
            | Self::AsyncGeneratorFunction(_)
            | Self::BuiltinFunction(_) => "function",
            Self::Iterator(_)
            | Self::Generator(_)
            | Self::AsyncFunctionObject(_)
            | Self::AsyncGeneratorObject(_)
            | Self::Promise(_)
            | Self::Accessor { .. } => "object",
        }
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Undefined => write!(f, "undefined"),
            Self::Null => write!(f, "null"),
            Self::Bool(b) => write!(f, "{b}"),
            Self::Int(n) => write!(f, "{n}"),
            Self::BigInt(n) => write!(f, "{n}"),
            Self::Float(fv) => write!(f, "{fv}"),
            Self::Str(s) => write!(f, "{s}"),
            Self::Symbol(id) => write!(f, "Symbol({})", id.0),
            Self::Object(id) => write!(f, "[object#{}]", id.0),
            Self::Function(idx) => write!(f, "[function#{idx}]"),
            Self::Closure(idx) => write!(f, "[closure#{idx}]"),
            Self::Iterator(idx) => write!(f, "[iterator#{idx}]"),
            Self::GeneratorFunction(idx) => write!(f, "[generatorfunction#{idx}]"),
            Self::Generator(idx) => write!(f, "[generator#{idx}]"),
            Self::AsyncFunction(idx) => write!(f, "[asyncfunction#{idx}]"),
            Self::AsyncFunctionObject(idx) => write!(f, "[asyncfunctionobject#{idx}]"),
            Self::AsyncGeneratorFunction(idx) => write!(f, "[asyncgeneratorfunction#{idx}]"),
            Self::AsyncGeneratorObject(idx) => write!(f, "[asyncgeneratorobject#{idx}]"),
            Self::Promise(idx) => write!(f, "[promise#{idx}]"),
            Self::BuiltinFunction(builtin) => write!(f, "[builtin:{}]", builtin.display_name()),
            Self::Accessor { .. } => write!(f, "[accessor]"),
        }
    }
}

/// Opaque object identifier (heap index).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ObjectId(pub u32);

/// The GC remembered set (bd-28ezw) as one bit per heap index
/// (bd-9vouw.490): every reference write inserts its object, and the
/// `BTreeSet` it was searched a tree on each write, about 360 instructions,
/// 7% of an array-literal loop. Same members, same ascending order.
#[derive(Debug, Clone, Default)]
struct RememberedSet {
    words: Vec<u64>,
    len: usize,
}

impl RememberedSet {
    fn slot(object_id: &ObjectId) -> (usize, u64) {
        ((object_id.0 / 64) as usize, 1u64 << (object_id.0 % 64))
    }

    /// Add `object_id`; true when it was not a member.
    pub fn insert(&mut self, object_id: ObjectId) -> bool {
        let (word, mask) = Self::slot(&object_id);
        if word >= self.words.len() {
            self.words.resize(word + 1, 0);
        }
        let fresh = self.words[word] & mask == 0;
        if fresh {
            self.words[word] |= mask;
            self.len += 1;
        }
        fresh
    }

    pub fn contains(&self, object_id: &ObjectId) -> bool {
        let (word, mask) = Self::slot(object_id);
        self.words.get(word).is_some_and(|bits| bits & mask != 0)
    }

    /// Remove `object_id`; true when it was a member.
    pub fn remove(&mut self, object_id: &ObjectId) -> bool {
        let (word, mask) = Self::slot(object_id);
        let Some(bits) = self.words.get_mut(word) else {
            return false;
        };
        let present = *bits & mask != 0;
        if present {
            *bits &= !mask;
            self.len -= 1;
        }
        present
    }

    pub fn clear(&mut self) {
        self.words.clear();
        self.len = 0;
    }

    pub fn len(&self) -> usize {
        self.len
    }

    /// The members in ascending order.
    pub fn iter(&self) -> impl Iterator<Item = ObjectId> + '_ {
        self.words.iter().enumerate().flat_map(|(word, &bits)| {
            (0..64u32)
                .filter(move |bit| bits & (1u64 << bit) != 0)
                .map(move |bit| ObjectId(word as u32 * 64 + bit))
        })
    }

    pub fn retain(&mut self, mut keep: impl FnMut(&ObjectId) -> bool) {
        let dropped = self.iter().filter(|id| !keep(id)).collect::<Vec<_>>();
        for object_id in &dropped {
            self.remove(object_id);
        }
    }
}

impl PartialEq for RememberedSet {
    /// Set equality: trailing empty words (left by `remove`) do not count.
    fn eq(&self, other: &Self) -> bool {
        self.len == other.len && self.iter().eq(other.iter())
    }
}

impl Eq for RememberedSet {}

/// The visited set of one prototype-chain walk, with no heap allocation for
/// its first [`CHAIN_GUARD_INLINE`] links (bd-9vouw.124): every [[Get]] that
/// missed an own property, and every label read, built a `BTreeSet` node.
#[derive(Debug, Default)]
struct ChainGuard {
    inline: [Option<ObjectId>; CHAIN_GUARD_INLINE],
    overflow: BTreeSet<ObjectId>,
}

const CHAIN_GUARD_INLINE: usize = 8;

impl ChainGuard {
    /// Records `id`; false when the walk already visited it (a cycle).
    fn insert(&mut self, id: ObjectId) -> bool {
        for slot in &mut self.inline {
            match slot {
                Some(seen) if *seen == id => return false,
                Some(_) => {}
                None => {
                    *slot = Some(id);
                    return true;
                }
            }
        }
        self.overflow.insert(id)
    }
}

/// Owned ArrayBuffer byte storage. Views store the ArrayBuffer ObjectId and
/// read/write through this backing so mutations stay shared.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArrayBufferBacking {
    pub bytes: Vec<u8>,
    /// IFC label for the bytes themselves. Register-only labels are not
    /// sufficient for mutable binary storage: a Secret value written through
    /// one Buffer/TypedArray view must remain Secret when read through any
    /// alias of the same backing store.
    #[serde(default = "public_ifc_label")]
    pub label: Label,
    /// ES2024 25.1.3.1 [[ArrayBufferMaxByteLength]]: present for a resizable
    /// ArrayBuffer or a growable SharedArrayBuffer (bd-9vouw.256).
    #[serde(default)]
    pub max_byte_length: Option<usize>,
    /// ES2024 25.1.3.5 IsDetachedBuffer: `transfer` moved the bytes out, so
    /// `bytes` is empty and every view is out of bounds (bd-9vouw.256).
    #[serde(default)]
    pub detached: bool,
    /// The typed arrays and DataViews over a resizable buffer, whose cached
    /// lengths `resize`/`grow` refresh. Weak: object ids are never reused,
    /// so a collected view's id reads as absent and is dropped then.
    #[serde(default)]
    pub views: Vec<ObjectId>,
}

fn public_ifc_label() -> Label {
    Label::Public
}

fn default_max_console_bytes() -> usize {
    DEFAULT_MAX_CONSOLE_BYTES
}

impl Default for ArrayBufferBacking {
    fn default() -> Self {
        Self::with_bytes(Vec::new())
    }
}

impl ArrayBufferBacking {
    pub fn new_zeroed(byte_length: usize) -> Self {
        Self::with_bytes(vec![0; byte_length])
    }

    /// A fixed-length, attached backing that owns `bytes`.
    pub fn with_bytes(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            label: Label::Public,
            max_byte_length: None,
            detached: false,
            views: Vec::new(),
        }
    }

    pub fn byte_length(&self) -> usize {
        self.bytes.len()
    }
}

/// BotGuard v1 typed-array families backed by ArrayBuffer bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TypedArrayKind {
    Uint8,
    Int32,
    Uint32,
    Int8,
    Uint8Clamped,
    Int16,
    Uint16,
    Float32,
    Float64,
    /// ES2020 22.2: 64-bit integer elements read as BigInt values.
    BigInt64,
    BigUint64,
}

impl TypedArrayKind {
    fn from_builtin_capability(capability: &str) -> Option<Self> {
        match capability {
            "builtin:Uint8Array" => Some(Self::Uint8),
            "builtin:Int32Array" => Some(Self::Int32),
            "builtin:Uint32Array" => Some(Self::Uint32),
            "builtin:Int8Array" => Some(Self::Int8),
            "builtin:Uint8ClampedArray" => Some(Self::Uint8Clamped),
            "builtin:Int16Array" => Some(Self::Int16),
            "builtin:Uint16Array" => Some(Self::Uint16),
            "builtin:Float32Array" => Some(Self::Float32),
            "builtin:Float64Array" => Some(Self::Float64),
            "builtin:BigInt64Array" => Some(Self::BigInt64),
            "builtin:BigUint64Array" => Some(Self::BigUint64),
            _ => None,
        }
    }

    fn from_type_name(type_name: &str) -> Option<Self> {
        match type_name {
            "Uint8Array" => Some(Self::Uint8),
            "Int32Array" => Some(Self::Int32),
            "Uint32Array" => Some(Self::Uint32),
            "Int8Array" => Some(Self::Int8),
            "Uint8ClampedArray" => Some(Self::Uint8Clamped),
            "Int16Array" => Some(Self::Int16),
            "Uint16Array" => Some(Self::Uint16),
            "Float32Array" => Some(Self::Float32),
            "Float64Array" => Some(Self::Float64),
            "BigInt64Array" => Some(Self::BigInt64),
            "BigUint64Array" => Some(Self::BigUint64),
            _ => None,
        }
    }

    fn type_name(self) -> &'static str {
        match self {
            Self::Uint8 => "Uint8Array",
            Self::Int32 => "Int32Array",
            Self::Uint32 => "Uint32Array",
            Self::Int8 => "Int8Array",
            Self::Uint8Clamped => "Uint8ClampedArray",
            Self::Int16 => "Int16Array",
            Self::Uint16 => "Uint16Array",
            Self::Float32 => "Float32Array",
            Self::Float64 => "Float64Array",
            Self::BigInt64 => "BigInt64Array",
            Self::BigUint64 => "BigUint64Array",
        }
    }

    fn element_size(self) -> usize {
        match self {
            Self::Uint8 | Self::Int8 | Self::Uint8Clamped => 1,
            Self::Int16 | Self::Uint16 => 2,
            Self::Int32 | Self::Uint32 | Self::Float32 => 4,
            Self::Float64 | Self::BigInt64 | Self::BigUint64 => 8,
        }
    }

    /// ES2020 22.2 [[ContentType]] BigInt: elements are BigInts, and a
    /// BigInt array never mixes with a Number one (set, construction).
    fn is_bigint(self) -> bool {
        matches!(self, Self::BigInt64 | Self::BigUint64)
    }
}

/// View over an ArrayBuffer backing store. `byte_length` and `length` are
/// the view's current lengths: 0 while it is out of bounds (bd-9vouw.256).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypedArrayView {
    pub kind: TypedArrayKind,
    pub buffer: ObjectId,
    pub byte_offset: usize,
    pub byte_length: usize,
    pub length: usize,
    /// Internal Node Buffer brand. This is deliberately not a JS property:
    /// guest writes must not be able to forge or erase Buffer identity.
    #[serde(default)]
    pub is_buffer: bool,
    /// Present for a view over a resizable or detached buffer.
    #[serde(default)]
    pub bounds: Option<ViewBounds>,
}

/// Byte-addressed view over an ArrayBuffer backing store; `byte_length` is
/// its current length, as for [`TypedArrayView`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataViewView {
    pub buffer: ObjectId,
    pub byte_offset: usize,
    pub byte_length: usize,
    #[serde(default)]
    pub bounds: Option<ViewBounds>,
}

/// bd-9vouw.256: how a view over a resizable buffer (or one detached by
/// `transfer`) relates to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewBounds {
    /// [[ArrayLength]] in elements (typed array) or [[ByteLength]] in bytes
    /// (DataView); `None` is auto: the view tracks the buffer's length.
    pub fixed_length: Option<usize>,
    /// ES2024 10.4.5.12 IsTypedArrayOutOfBounds / 25.3.1.3 IsViewOutOfBounds.
    pub out_of_bounds: bool,
}

impl ViewBounds {
    /// The view's element count over `buffer_len` bytes (ES2024 10.4.5.14
    /// TypedArrayLength, 25.3.1.2 GetViewByteLength with 1-byte elements),
    /// or `None` when it is out of bounds.
    fn current_length(
        self,
        byte_offset: usize,
        element_size: usize,
        buffer_len: usize,
        detached: bool,
    ) -> Option<usize> {
        if detached {
            return None;
        }
        match self.fixed_length {
            None => (byte_offset <= buffer_len).then(|| (buffer_len - byte_offset) / element_size),
            Some(length) => {
                let end = length.checked_mul(element_size)?.checked_add(byte_offset)?;
                (end <= buffer_len).then_some(length)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DataViewIntegerKind {
    Uint8,
    Int32,
    Uint32,
    // Served through `BuiltinFunctionKind::DataViewMethod` (floats and
    // BigInts too, despite the enum's name).
    Int8,
    Int16,
    Uint16,
    Float32,
    Float64,
    BigInt64,
    BigUint64,
}

/// `%TypedArray%.prototype` methods served by
/// [`BuiltinFunctionKind::TypedArrayMethod`]: the ones that must build a
/// typed array of the receiver's kind or reorder its elements in place. The
/// read-only and callback methods (join, indexOf, forEach, reduce, ...) are
/// the generic `Array.prototype` builtins, which read typed arrays through
/// `array_like_length` / `array_index_value`.
const TYPED_ARRAY_METHODS: [&str; 7] = [
    "map",
    "filter",
    "reverse",
    "sort",
    // ES2023 change array by copy (bd-9vouw.258).
    "toReversed",
    "toSorted",
    "with",
];

/// DataView accessors served by [`BuiltinFunctionKind::DataViewMethod`].
const DATA_VIEW_METHODS: [&str; 14] = [
    "getInt8",
    "setInt8",
    "getInt16",
    "setInt16",
    "getUint16",
    "setUint16",
    "getFloat32",
    "setFloat32",
    "getFloat64",
    "setFloat64",
    "getBigInt64",
    "setBigInt64",
    "getBigUint64",
    "setBigUint64",
];

/// `Buffer.prototype` methods served by
/// [`BuiltinFunctionKind::BufferNumericMethod`] (bd-9vouw.437): `write`,
/// and the numeric accessors the dedicated kinds do not serve: 8- and 16-bit
/// signed, variable width (`readIntLE(offset, byteLength)`), float, double
/// and 64-bit BigInt, and the lowercase `Uint` aliases Node also defines.
const BUFFER_NUMERIC_METHODS: &[&str] = &[
    "write",
    "readInt8",
    "writeInt8",
    "readUint8",
    "writeUint8",
    "readInt16LE",
    "readInt16BE",
    "writeInt16LE",
    "writeInt16BE",
    "readUint16LE",
    "readUint16BE",
    "writeUint16LE",
    "writeUint16BE",
    "readUint32LE",
    "readUint32BE",
    "writeUint32LE",
    "writeUint32BE",
    "readIntLE",
    "readIntBE",
    "writeIntLE",
    "writeIntBE",
    "readUIntLE",
    "readUIntBE",
    "writeUIntLE",
    "writeUIntBE",
    "readUintLE",
    "readUintBE",
    "writeUintLE",
    "writeUintBE",
    "readFloatLE",
    "readFloatBE",
    "writeFloatLE",
    "writeFloatBE",
    "readDoubleLE",
    "readDoubleBE",
    "writeDoubleLE",
    "writeDoubleBE",
    "readBigInt64LE",
    "readBigInt64BE",
    "writeBigInt64LE",
    "writeBigInt64BE",
    "readBigUInt64LE",
    "readBigUInt64BE",
    "writeBigUInt64LE",
    "writeBigUInt64BE",
    "readBigUint64LE",
    "readBigUint64BE",
    "writeBigUint64LE",
    "writeBigUint64BE",
];

/// The number format of a [`BUFFER_NUMERIC_METHODS`] accessor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BufferNumberFormat {
    Int {
        width: usize,
        signed: bool,
    },
    /// `readIntLE(offset, byteLength)`: 1 to 6 bytes.
    Variable {
        signed: bool,
    },
    Float32,
    Float64,
    BigInt64 {
        signed: bool,
    },
}

impl BufferNumberFormat {
    /// `(write, format, little_endian)` of an accessor name: the 8-bit
    /// names have no byte-order suffix, every other one has `LE` or `BE`.
    fn parse(name: &str) -> Option<(bool, Self, bool)> {
        let (write, rest) = match name.strip_prefix("read") {
            Some(rest) => (false, rest),
            None => (true, name.strip_prefix("write")?),
        };
        let (body, little_endian, suffixed) = if let Some(body) = rest.strip_suffix("LE") {
            (body, true, true)
        } else if let Some(body) = rest.strip_suffix("BE") {
            (body, false, true)
        } else {
            (rest, false, false)
        };
        let format = match body {
            "Int8" => Self::Int {
                width: 1,
                signed: true,
            },
            "UInt8" | "Uint8" => Self::Int {
                width: 1,
                signed: false,
            },
            "Int16" => Self::Int {
                width: 2,
                signed: true,
            },
            "UInt16" | "Uint16" => Self::Int {
                width: 2,
                signed: false,
            },
            "Int32" => Self::Int {
                width: 4,
                signed: true,
            },
            "UInt32" | "Uint32" => Self::Int {
                width: 4,
                signed: false,
            },
            "Int" => Self::Variable { signed: true },
            "UInt" | "Uint" => Self::Variable { signed: false },
            "Float" => Self::Float32,
            "Double" => Self::Float64,
            "BigInt64" => Self::BigInt64 { signed: true },
            "BigUInt64" | "BigUint64" => Self::BigInt64 { signed: false },
            _ => return None,
        };
        let one_byte = matches!(format, Self::Int { width: 1, .. });
        (one_byte != suffixed).then_some((write, format, little_endian))
    }

    /// The value of `width` little-endian bytes (`bytes` beyond `width`
    /// are zero).
    fn decode(self, bytes: [u8; 8], width: usize) -> Value {
        match self {
            Self::Int { signed, .. } | Self::Variable { signed } => {
                let unsigned = u64::from_le_bytes(bytes);
                let bits = width * 8;
                let negative = signed && unsigned & (1u64 << (bits - 1)) != 0;
                let value = unsigned as i64;
                Value::Int(if negative {
                    value - (1i64 << bits)
                } else {
                    value
                })
            }
            Self::Float32 => js_number_to_value(f64::from(f32::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3],
            ]))),
            Self::Float64 => js_number_to_value(f64::from_le_bytes(bytes)),
            Self::BigInt64 { signed: true } => {
                Value::BigInt(Arc::from(i64::from_le_bytes(bytes).to_string().as_str()))
            }
            Self::BigInt64 { signed: false } => {
                Value::BigInt(Arc::from(u64::from_le_bytes(bytes).to_string().as_str()))
            }
        }
    }
}

/// A number as Node's ERR_OUT_OF_RANGE messages print it: an integer beyond
/// 2 ** 32 with `_` between digit groups (`4_294_967_296`).
fn node_out_of_range_received(number: f64) -> String {
    if number.is_infinite() {
        return if number > 0.0 {
            "Infinity"
        } else {
            "-Infinity"
        }
        .to_string();
    }
    if number.is_nan() || number.fract() != 0.0 || number.abs() <= 4_294_967_296.0 {
        return format!("{number}");
    }
    group_decimal_digits(&format!("{number}"))
}

/// `digits` (an optional `-` and decimal digits) with `_` between groups of
/// three, as Node prints a large number or BigInt in a range error.
fn group_decimal_digits(digits: &str) -> String {
    let (sign, digits) = digits
        .strip_prefix('-')
        .map_or(("", digits), |rest| ("-", rest));
    let mut grouped = String::with_capacity(digits.len() + digits.len() / 3 + 1);
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index) % 3 == 0 {
            grouped.push('_');
        }
        grouped.push(digit);
    }
    format!("{sign}{grouped}")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BufferIntegerKind {
    UInt8,
    UInt16,
    Int32,
    UInt32,
}

impl BufferIntegerKind {
    fn byte_width(self) -> usize {
        match self {
            Self::UInt8 => 1,
            Self::UInt16 => 2,
            Self::Int32 | Self::UInt32 => 4,
        }
    }
}

impl DataViewIntegerKind {
    fn byte_width(self) -> usize {
        match self {
            Self::Uint8 | Self::Int8 => 1,
            Self::Int16 | Self::Uint16 => 2,
            Self::Int32 | Self::Uint32 | Self::Float32 => 4,
            Self::Float64 | Self::BigInt64 | Self::BigUint64 => 8,
        }
    }

    fn method_name(self, setter: bool) -> &'static str {
        match (self, setter) {
            (Self::Uint8, false) => "getUint8",
            (Self::Uint8, true) => "setUint8",
            (Self::Int32, false) => "getInt32",
            (Self::Int32, true) => "setInt32",
            (Self::Uint32, false) => "getUint32",
            (Self::Uint32, true) => "setUint32",
            (Self::Int8, false) => "getInt8",
            (Self::Int8, true) => "setInt8",
            (Self::Int16, false) => "getInt16",
            (Self::Int16, true) => "setInt16",
            (Self::Uint16, false) => "getUint16",
            (Self::Uint16, true) => "setUint16",
            (Self::Float32, false) => "getFloat32",
            (Self::Float32, true) => "setFloat32",
            (Self::Float64, false) => "getFloat64",
            (Self::Float64, true) => "setFloat64",
            (Self::BigInt64, false) => "getBigInt64",
            (Self::BigInt64, true) => "setBigInt64",
            (Self::BigUint64, false) => "getBigUint64",
            (Self::BigUint64, true) => "setBigUint64",
        }
    }

    /// The element kind and setter flag of a [`DATA_VIEW_METHODS`] name.
    fn from_method_name(name: &str) -> Option<(Self, bool)> {
        [
            Self::Int8,
            Self::Int16,
            Self::Uint16,
            Self::Float32,
            Self::Float64,
            Self::BigInt64,
            Self::BigUint64,
        ]
        .into_iter()
        .find_map(|kind| {
            [false, true]
                .into_iter()
                .find(|setter| kind.method_name(*setter) == name)
                .map(|setter| (kind, setter))
        })
    }
}

// ---------------------------------------------------------------------------
// HeapObject — simplified object model
// ---------------------------------------------------------------------------

/// Private executable property key for dynamic IR operations.
///
/// Public compatibility and hook APIs remain `String`/`&str`; this carrier is
/// deliberately private so exact UTF-16 strings and Symbol identities reach
/// the heap without widening those frozen surfaces.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum RuntimePropertyKey {
    String(JsString),
    Symbol(SymbolId),
}

impl From<&str> for RuntimePropertyKey {
    fn from(value: &str) -> Self {
        Self::String(JsString::from(value))
    }
}

impl From<&String> for RuntimePropertyKey {
    fn from(value: &String) -> Self {
        Self::from(value.as_str())
    }
}

impl From<&RuntimePropertyKey> for RuntimePropertyKey {
    fn from(value: &RuntimePropertyKey) -> Self {
        value.clone()
    }
}

fn core_symbol_id(symbol: SymbolId) -> CoreSymbolId {
    CoreSymbolId(symbol.0)
}

fn engine_symbol_id(symbol: CoreSymbolId) -> SymbolId {
    SymbolId(symbol.0)
}

const UPPER_HEX: &[u8; 16] = b"0123456789ABCDEF";

/// A physical register the compact numeric operand guards found eligible for
/// a static write; only those checks make one (bd-9vouw.504).
#[derive(Debug, Clone, Copy)]
struct StaticWriteSlot(usize);

fn decimal_u32_len(value: u32) -> usize {
    if value == 0 {
        1
    } else {
        value.ilog10() as usize + 1
    }
}

fn append_decimal_u32(bytes: &mut Vec<u8>, mut value: u32) {
    let mut digits = [0u8; 10];
    let mut start = digits.len();
    loop {
        start -= 1;
        digits[start] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    bytes.extend_from_slice(&digits[start..]);
}

impl RuntimePropertyKey {
    fn string(&self) -> Option<&JsString> {
        match self {
            Self::String(key) => Some(key),
            Self::Symbol(_) => None,
        }
    }

    fn as_str(&self) -> Option<&str> {
        self.string().and_then(JsString::as_str)
    }

    fn value(&self) -> Value {
        match self {
            Self::String(key) => Value::Str(key.clone()),
            Self::Symbol(symbol) => Value::Symbol(*symbol),
        }
    }

    fn diagnostic(&self) -> String {
        let Self::String(string) = self else {
            let Self::Symbol(symbol) = self else {
                unreachable!("RuntimePropertyKey variants are exhaustive")
            };
            return format!("~pk~s:{}", symbol.0);
        };
        if let Some(key) = self.as_str() {
            if key.starts_with("~pk~") {
                let mut diagnostic = String::with_capacity(6 + key.len().saturating_mul(2));
                diagnostic.push_str("~pk~u:");
                for byte in key.as_bytes() {
                    fmt::Write::write_fmt(&mut diagnostic, format_args!("{byte:02X}"))
                        .expect("writing hexadecimal bytes to String cannot fail");
                }
                return diagnostic;
            }
            return key.to_string();
        }
        let mut diagnostic = String::with_capacity(6 + string.utf16_len().saturating_mul(4));
        diagnostic.push_str("~pk~x:");
        for unit in string.encode_utf16() {
            fmt::Write::write_fmt(&mut diagnostic, format_args!("{unit:04X}"))
                .expect("writing hexadecimal code units to String cannot fail");
        }
        diagnostic
    }

    fn diagnostic_byte_len(&self) -> usize {
        match self {
            Self::Symbol(symbol) => 6 + decimal_u32_len(symbol.0),
            Self::String(string) => match self.as_str() {
                Some(key) if key.starts_with("~pk~") => 6 + key.len().saturating_mul(2),
                Some(key) => key.len(),
                None => 6 + string.utf16_len().saturating_mul(4),
            },
        }
    }

    fn append_diagnostic_bytes(&self, bytes: &mut Vec<u8>) {
        match self {
            Self::Symbol(symbol) => {
                bytes.extend_from_slice(b"~pk~s:");
                append_decimal_u32(bytes, symbol.0);
            }
            Self::String(string) => {
                if let Some(key) = self.as_str() {
                    if !key.starts_with("~pk~") {
                        bytes.extend_from_slice(key.as_bytes());
                        return;
                    }
                    bytes.extend_from_slice(b"~pk~u:");
                    for byte in key.as_bytes() {
                        bytes.push(UPPER_HEX[usize::from(byte >> 4)]);
                        bytes.push(UPPER_HEX[usize::from(byte & 0x0F)]);
                    }
                    return;
                }
                bytes.extend_from_slice(b"~pk~x:");
                for unit in string.encode_utf16() {
                    bytes.push(UPPER_HEX[usize::from((unit >> 12) & 0x0F)]);
                    bytes.push(UPPER_HEX[usize::from((unit >> 8) & 0x0F)]);
                    bytes.push(UPPER_HEX[usize::from((unit >> 4) & 0x0F)]);
                    bytes.push(UPPER_HEX[usize::from(unit & 0x0F)]);
                }
            }
        }
    }
}

#[cfg(test)]
fn property_resolution_found_payload(
    key: &RuntimePropertyKey,
    object_id: ObjectId,
    depth: u32,
) -> Vec<u8> {
    let mut payload = Vec::new();
    write_property_resolution_found_payload(&mut payload, key, object_id, depth);
    payload
}

#[cfg(test)]
thread_local! {
    /// Sends every own-property read through the generic [[Get]], so a test
    /// can compare it with the fast path on the same object.
    static FORCE_GENERIC_OWN_PROPERTY_READS: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
    /// Sends every store through the generic [[Set]] (bd-9vouw.504).
    static FORCE_GENERIC_STORES: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// How many small array indices keep a shared decimal key.
const SMALL_INDEX_KEYS: usize = 1024;

/// The decimal property key of a small non-negative integer, shared per
/// thread (bd-9vouw.504): `a[i]` formatted a String and then made a shared
/// copy of it on every access. Key identity is never observable; the keys
/// are filled on first use, at most SMALL_INDEX_KEYS of them.
fn small_index_key(number: i64) -> Option<JsString> {
    thread_local! {
        static KEYS: std::cell::RefCell<Vec<Option<JsString>>> =
            const { std::cell::RefCell::new(Vec::new()) };
    }
    let index = usize::try_from(number)
        .ok()
        .filter(|index| *index < SMALL_INDEX_KEYS)?;
    KEYS.with(|keys| {
        let mut keys = keys.borrow_mut();
        if keys.len() <= index {
            keys.resize(index + 1, None);
        }
        Some(
            keys[index]
                .get_or_insert_with(|| JsString::from(index.to_string()))
                .clone(),
        )
    })
}

/// Replace `payload`'s contents with the found-property witness event's bytes.
fn write_property_resolution_found_payload(
    payload: &mut Vec<u8>,
    key: &RuntimePropertyKey,
    object_id: ObjectId,
    depth: u32,
) {
    payload.clear();
    payload.reserve(
        b"property_found:key=".len()
            + key.diagnostic_byte_len()
            + b",object_id=".len()
            + decimal_u32_len(object_id.0)
            + b",depth=".len()
            + decimal_u32_len(depth),
    );
    payload.extend_from_slice(b"property_found:key=");
    key.append_diagnostic_bytes(payload);
    payload.extend_from_slice(b",object_id=");
    append_decimal_u32(payload, object_id.0);
    payload.extend_from_slice(b",depth=");
    append_decimal_u32(payload, depth);
}

/// The most property-witness scratch capacity an interpreter keeps between
/// reads; a longer key's buffer is dropped after its event.
const PROPERTY_WITNESS_SCRATCH_MAX_CAPACITY: usize = 256;

/// The most argument slots each call-argument scratch vector keeps between
/// calls; a call with more arguments drops its vectors after the call.
const CALL_ARGUMENT_SCRATCH_MAX_CAPACITY: usize = 64;

/// Slots per heap chunk. A full chunk whose objects were all reclaimed is
/// released as a whole (bd-9vouw.57 phase B), so memory follows the live set
/// rather than the number of allocations.
const HEAP_CHUNK_SLOTS: usize = 1024;

#[derive(Debug, Clone, Default)]
struct HeapChunk {
    slots: Vec<Option<Box<HeapSlot>>>,
    live: usize,
}

/// A live object with the estimate the heap last recorded for it.
#[derive(Debug, Clone)]
struct HeapSlot {
    object: HeapObject,
    /// `estimate_heap_object_bytes(&object)` when last measured.
    measured_bytes: Cell<u64>,
    /// Borrowed mutably since it was last measured.
    dirty: Cell<bool>,
    /// Derived admission proof for dense array moves. Every mutable object
    /// borrow invalidates it, including low-level embedder writes. Keeping it
    /// on the slot leaves HeapObject equality and checkpoint bytes unchanged.
    dense_moves_plain: Cell<Option<bool>>,
}

impl HeapSlot {
    fn new(object: HeapObject) -> Box<Self> {
        let measured_bytes = Cell::new(InterpreterCore::estimate_heap_object_bytes(&object));
        Box::new(Self {
            object,
            measured_bytes,
            dirty: Cell::new(false),
            dense_moves_plain: Cell::new(None),
        })
    }
}

/// The interpreter heap. `ObjectId(n)` names slot `n`; the collector
/// (bd-9vouw.57) empties the slot of an unreachable object.
///
/// Ids are append-only and never reused. The engine's transactional
/// allocations roll back by truncating to a previous length, and a missed GC
/// root shows up as a missing object (`get` returns `None`, indexing panics and
/// names the id), never as silent aliasing of a newer object. A reclaimed slot
/// costs one pointer until every object in its chunk is gone; then the chunk is
/// released.
///
/// The heap also keeps the sum of its objects' memory estimates. Every
/// mutable borrow of an object marks it dirty, and `estimated_bytes`
/// re-measures only the dirty objects, so a full memory re-derivation costs
/// O(objects changed) instead of O(heap).
#[derive(Debug, Clone, Default)]
pub struct Heap {
    /// `None`: a released chunk, every slot of which was reclaimed.
    chunks: Vec<Option<HeapChunk>>,
    len: usize,
    live: usize,
    /// Sum of `measured_bytes` over live slots.
    measured_bytes: Cell<u64>,
    /// Ids of slots marked dirty; a slot is listed at most once.
    dirty: RefCell<Vec<usize>>,
}

impl Heap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of slots ever allocated: the next `ObjectId` is `len()`.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Number of objects that have not been reclaimed.
    pub fn live_len(&self) -> usize {
        self.live
    }

    /// Chunks still holding at least one live object or the allocation tail.
    pub fn resident_chunks(&self) -> usize {
        self.chunks.iter().filter(|chunk| chunk.is_some()).count()
    }

    fn slot(&self, index: usize) -> Option<&HeapSlot> {
        self.chunks
            .get(index / HEAP_CHUNK_SLOTS)?
            .as_ref()?
            .slots
            .get(index % HEAP_CHUNK_SLOTS)?
            .as_deref()
    }

    pub fn get(&self, index: usize) -> Option<&HeapObject> {
        self.slot(index).map(|slot| &slot.object)
    }

    pub fn get_mut(&mut self, index: usize) -> Option<&mut HeapObject> {
        let slot = self
            .chunks
            .get_mut(index / HEAP_CHUNK_SLOTS)?
            .as_mut()?
            .slots
            .get_mut(index % HEAP_CHUNK_SLOTS)?
            .as_deref_mut()?;
        if !slot.dirty.replace(true) {
            self.dirty.get_mut().push(index);
        }
        slot.dense_moves_plain.set(None);
        Some(&mut slot.object)
    }

    /// Sum of the memory estimates of the live objects, re-measuring only
    /// objects borrowed mutably since they were last measured.
    fn estimated_bytes(&self) -> u64 {
        let mut total = self.measured_bytes.get();
        for index in self.dirty.borrow_mut().drain(..) {
            // A slot reclaimed or popped since it was listed is skipped; its
            // last measurement left the total when it was removed.
            if let Some(slot) = self.slot(index)
                && slot.dirty.replace(false)
            {
                let bytes = InterpreterCore::estimate_heap_object_bytes(&slot.object);
                total = total
                    .saturating_sub(slot.measured_bytes.replace(bytes))
                    .saturating_add(bytes);
            }
        }
        self.measured_bytes.set(total);
        total
    }

    fn forget(&mut self, slot: &HeapSlot) {
        let total = self.measured_bytes.get_mut();
        *total = total.saturating_sub(slot.measured_bytes.get());
    }

    pub fn push(&mut self, object: HeapObject) {
        if self.len.is_multiple_of(HEAP_CHUNK_SLOTS) {
            self.chunks.push(Some(HeapChunk {
                slots: Vec::with_capacity(HEAP_CHUNK_SLOTS),
                live: 0,
            }));
        }
        let slot = HeapSlot::new(object);
        let total = self.measured_bytes.get_mut();
        *total = total.saturating_add(slot.measured_bytes.get());
        // Only a full chunk is ever released, so the tail chunk is resident.
        let chunk = self
            .chunks
            .last_mut()
            .and_then(Option::as_mut)
            .expect("the allocation tail chunk is resident");
        chunk.slots.push(Some(slot));
        chunk.live += 1;
        self.len += 1;
        self.live += 1;
    }

    /// Remove the last slot, returning its object if it was live.
    pub fn pop(&mut self) -> Option<HeapObject> {
        let index = self.len.checked_sub(1)?;
        let chunk_index = index / HEAP_CHUNK_SLOTS;
        let chunk = self.chunks.get_mut(chunk_index)?;
        if chunk.is_none() {
            // Popping from a released chunk: its remaining slots are dead.
            *chunk = Some(HeapChunk {
                slots: vec![None; HEAP_CHUNK_SLOTS],
                live: 0,
            });
        }
        let chunk = chunk.as_mut().expect("chunk was just made resident");
        let slot = chunk.slots.pop().flatten();
        if slot.is_some() {
            chunk.live -= 1;
            self.live -= 1;
        }
        self.len = index;
        if self.len.is_multiple_of(HEAP_CHUNK_SLOTS) {
            self.chunks.truncate(self.len / HEAP_CHUNK_SLOTS);
        }
        let slot = slot?;
        self.forget(&slot);
        Some(slot.object)
    }

    pub fn truncate(&mut self, len: usize) {
        while self.len > len {
            self.pop();
        }
    }

    /// Live objects in id order (reclaimed slots are skipped).
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = &HeapObject> {
        self.chunks
            .iter()
            .flatten()
            .flat_map(|chunk| chunk.slots.iter())
            .filter_map(|slot| slot.as_deref().map(|slot| &slot.object))
    }

    /// Live objects with their slot index.
    pub fn iter_live(&self) -> impl Iterator<Item = (usize, &HeapObject)> {
        self.chunks
            .iter()
            .enumerate()
            .filter_map(|(chunk_index, chunk)| chunk.as_ref().map(|chunk| (chunk_index, chunk)))
            .flat_map(|(chunk_index, chunk)| {
                chunk
                    .slots
                    .iter()
                    .enumerate()
                    .filter_map(move |(offset, slot)| {
                        slot.as_deref()
                            .map(|slot| (chunk_index * HEAP_CHUNK_SLOTS + offset, &slot.object))
                    })
            })
    }

    pub fn is_reclaimed(&self, index: usize) -> bool {
        index < self.len && self.get(index).is_none()
    }

    /// Empty the slot of every live object `keep` rejects, handing each object
    /// to `reclaimed`. Only resident chunks are visited, and a full chunk left
    /// with no live object is released.
    fn sweep(
        &mut self,
        mut keep: impl FnMut(usize) -> bool,
        mut reclaimed: impl FnMut(&HeapObject),
    ) {
        let total = self.measured_bytes.get_mut();
        for (chunk_index, entry) in self.chunks.iter_mut().enumerate() {
            let Some(chunk) = entry else {
                continue;
            };
            let base = chunk_index * HEAP_CHUNK_SLOTS;
            for (offset, slot) in chunk.slots.iter_mut().enumerate() {
                if slot.is_some() && !keep(base + offset) {
                    let slot = slot.take().expect("slot was checked live");
                    *total = total.saturating_sub(slot.measured_bytes.get());
                    reclaimed(&slot.object);
                    chunk.live -= 1;
                    self.live -= 1;
                }
            }
            if chunk.live == 0 && chunk.slots.len() == HEAP_CHUNK_SLOTS {
                *entry = None;
            }
        }
    }
}

/// Heaps are equal when they hold the same objects under the same ids,
/// whatever their chunks' release state.
impl PartialEq for Heap {
    fn eq(&self, other: &Self) -> bool {
        self.len == other.len && (0..self.len).all(|index| self.get(index) == other.get(index))
    }
}

impl Eq for Heap {}

impl From<Vec<HeapObject>> for Heap {
    fn from(objects: Vec<HeapObject>) -> Self {
        let mut heap = Self::new();
        for object in objects {
            heap.push(object);
        }
        heap
    }
}

/// Serializes like the `Vec<HeapObject>` it replaced: one array element per
/// slot, with `null` for a reclaimed slot.
impl Serialize for Heap {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq((0..self.len).map(|index| self.get(index)))
    }
}

/// A heap equals the object list it holds when no slot is reclaimed.
impl PartialEq<Vec<HeapObject>> for Heap {
    fn eq(&self, other: &Vec<HeapObject>) -> bool {
        self.len == other.len()
            && other
                .iter()
                .enumerate()
                .all(|(index, object)| self.get(index) == Some(object))
    }
}

impl std::ops::Index<usize> for Heap {
    type Output = HeapObject;

    fn index(&self, index: usize) -> &HeapObject {
        match self.get(index) {
            Some(object) => object,
            None if index < self.len => panic!("use of reclaimed heap object {index}"),
            None => panic!("heap object {index} out of bounds ({})", self.len),
        }
    }
}

impl std::ops::IndexMut<usize> for Heap {
    fn index_mut(&mut self, index: usize) -> &mut HeapObject {
        let len = self.len;
        if index >= len {
            panic!("heap object {index} out of bounds ({len})");
        }
        self.get_mut(index)
            .unwrap_or_else(|| panic!("use of reclaimed heap object {index}"))
    }
}

/// The memory components that the running and the by-walk re-derivations of
/// the base estimate obtain differently: running totals versus full walks.
struct MemoryComponents {
    heap: u64,
    async_functions: u64,
    iterators: u64,
    generators: u64,
    async_generators: u64,
    scope_chain: u64,
    closures: u64,
    promise_runtime: u64,
}

/// Entries per chunk of a [`ReclaimableTable`].
const TABLE_CHUNK_SLOTS: usize = HEAP_CHUNK_SLOTS;

#[derive(Debug, Clone)]
struct TableSlot<T> {
    value: T,
    /// The table's `measure` of `value` when last measured.
    measured_bytes: Cell<u64>,
    /// Borrowed mutably since it was last measured.
    dirty: Cell<bool>,
}

#[derive(Debug, Clone)]
struct TableChunk<T> {
    slots: Vec<Option<TableSlot<T>>>,
    live: usize,
}

/// An append-only id table whose entries the collector can reclaim
/// (bd-9vouw.57), keeping the running sum of its entries' memory estimates.
///
/// Ids are never reused: a reclaimed id reads as `None`, and indexing it
/// panics naming the table and the id. A full chunk whose entries are all
/// reclaimed is released. Every mutable borrow marks the entry dirty, and
/// `estimated_bytes` re-measures only dirty entries, so a full memory
/// re-derivation does not walk the table.
#[derive(Debug, Clone)]
struct ReclaimableTable<T> {
    name: &'static str,
    measure: fn(&T) -> u64,
    /// `None`: a released chunk, every entry of which was reclaimed.
    chunks: Vec<Option<TableChunk<T>>>,
    len: usize,
    live: usize,
    /// Sum of `measured_bytes` over live entries.
    measured_bytes: Cell<u64>,
    /// Ids of entries marked dirty; an entry is listed at most once.
    dirty: RefCell<Vec<usize>>,
}

impl<T> ReclaimableTable<T> {
    fn new(name: &'static str, measure: fn(&T) -> u64) -> Self {
        Self {
            name,
            measure,
            chunks: Vec::new(),
            len: 0,
            live: 0,
            measured_bytes: Cell::new(0),
            dirty: RefCell::new(Vec::new()),
        }
    }

    /// Number of ids ever allocated: the next id is `len()`.
    fn len(&self) -> usize {
        self.len
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The entry with id 0, as `<[T]>::first` read it.
    #[cfg(test)]
    fn first(&self) -> Option<&T> {
        self.get(0)
    }

    /// The entry with the highest id, as `<[T]>::last` read it.
    #[cfg(test)]
    fn last(&self) -> Option<&T> {
        self.get(self.len.checked_sub(1)?)
    }

    fn slot(&self, index: usize) -> Option<&TableSlot<T>> {
        self.chunks
            .get(index / TABLE_CHUNK_SLOTS)?
            .as_ref()?
            .slots
            .get(index % TABLE_CHUNK_SLOTS)?
            .as_ref()
    }

    fn get(&self, index: usize) -> Option<&T> {
        self.slot(index).map(|slot| &slot.value)
    }

    fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        let slot = self
            .chunks
            .get_mut(index / TABLE_CHUNK_SLOTS)?
            .as_mut()?
            .slots
            .get_mut(index % TABLE_CHUNK_SLOTS)?
            .as_mut()?;
        if !slot.dirty.replace(true) {
            self.dirty.get_mut().push(index);
        }
        Some(&mut slot.value)
    }

    fn push(&mut self, value: T) {
        if self.len.is_multiple_of(TABLE_CHUNK_SLOTS) {
            self.chunks.push(Some(TableChunk {
                slots: Vec::new(),
                live: 0,
            }));
        }
        let measured = (self.measure)(&value);
        self.measured_bytes
            .set(self.measured_bytes.get().saturating_add(measured));
        // Only a full chunk is ever released, so the tail chunk is resident.
        let chunk = self
            .chunks
            .last_mut()
            .and_then(Option::as_mut)
            .expect("the table's tail chunk is resident");
        chunk.slots.push(Some(TableSlot {
            value,
            measured_bytes: Cell::new(measured),
            dirty: Cell::new(false),
        }));
        chunk.live += 1;
        self.len += 1;
        self.live += 1;
    }

    /// Remove the last id, returning its entry if it was live.
    fn pop(&mut self) -> Option<T> {
        let index = self.len.checked_sub(1)?;
        let chunk_index = index / TABLE_CHUNK_SLOTS;
        if self.chunks[chunk_index].is_none() {
            // Popping into a released chunk: its remaining entries are dead.
            self.chunks[chunk_index] = Some(TableChunk {
                slots: (0..TABLE_CHUNK_SLOTS).map(|_| None).collect(),
                live: 0,
            });
        }
        let chunk = self.chunks[chunk_index]
            .as_mut()
            .expect("chunk was just made resident");
        let slot = chunk.slots.pop().flatten();
        if slot.is_some() {
            chunk.live -= 1;
            self.live -= 1;
        }
        self.len = index;
        if self.len.is_multiple_of(TABLE_CHUNK_SLOTS) {
            self.chunks.truncate(self.len / TABLE_CHUNK_SLOTS);
        }
        let slot = slot?;
        self.measured_bytes.set(
            self.measured_bytes
                .get()
                .saturating_sub(slot.measured_bytes.get()),
        );
        Some(slot.value)
    }

    fn clear(&mut self) {
        while self.len > 0 {
            self.pop();
        }
    }

    /// Live entries in id order.
    fn iter(&self) -> impl Iterator<Item = &T> {
        self.chunks
            .iter()
            .flatten()
            .flat_map(|chunk| chunk.slots.iter())
            .filter_map(|slot| slot.as_ref().map(|slot| &slot.value))
    }

    /// Live entries with their ids.
    fn iter_live(&self) -> impl Iterator<Item = (usize, &T)> {
        self.chunks
            .iter()
            .enumerate()
            .filter_map(|(chunk_index, chunk)| chunk.as_ref().map(|chunk| (chunk_index, chunk)))
            .flat_map(|(chunk_index, chunk)| {
                chunk
                    .slots
                    .iter()
                    .enumerate()
                    .filter_map(move |(offset, slot)| {
                        slot.as_ref()
                            .map(|slot| (chunk_index * TABLE_CHUNK_SLOTS + offset, &slot.value))
                    })
            })
    }

    /// Live entries, each marked dirty.
    fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        let dirty = self.dirty.get_mut();
        for (chunk_index, chunk) in self.chunks.iter().enumerate() {
            let Some(chunk) = chunk else {
                continue;
            };
            for (offset, slot) in chunk.slots.iter().enumerate() {
                if let Some(slot) = slot
                    && !slot.dirty.replace(true)
                {
                    dirty.push(chunk_index * TABLE_CHUNK_SLOTS + offset);
                }
            }
        }
        self.chunks
            .iter_mut()
            .flatten()
            .flat_map(|chunk| chunk.slots.iter_mut())
            .filter_map(|slot| slot.as_mut().map(|slot| &mut slot.value))
    }

    /// Empty the entry of `index` and return it. A full chunk left with no
    /// live entry is released.
    fn reclaim(&mut self, index: usize) -> Option<T> {
        let chunk_index = index / TABLE_CHUNK_SLOTS;
        let chunk = self.chunks.get_mut(chunk_index)?.as_mut()?;
        let slot = chunk.slots.get_mut(index % TABLE_CHUNK_SLOTS)?.take()?;
        chunk.live -= 1;
        self.live -= 1;
        if chunk.live == 0 && chunk.slots.len() == TABLE_CHUNK_SLOTS {
            self.chunks[chunk_index] = None;
        }
        self.measured_bytes.set(
            self.measured_bytes
                .get()
                .saturating_sub(slot.measured_bytes.get()),
        );
        Some(slot.value)
    }

    /// Sum of the memory estimates of the live entries, re-measuring only
    /// entries borrowed mutably since they were last measured.
    fn estimated_bytes(&self) -> u64 {
        let mut total = self.measured_bytes.get();
        for index in self.dirty.borrow_mut().drain(..) {
            // An entry reclaimed or popped since it was listed is skipped; its
            // last measurement left the total when it was removed.
            if let Some(slot) = self.slot(index)
                && slot.dirty.replace(false)
            {
                let bytes = (self.measure)(&slot.value);
                total = total
                    .saturating_sub(slot.measured_bytes.replace(bytes))
                    .saturating_add(bytes);
            }
        }
        self.measured_bytes.set(total);
        total
    }
}

impl<T> std::ops::Index<usize> for ReclaimableTable<T> {
    type Output = T;

    fn index(&self, index: usize) -> &T {
        match self.get(index) {
            Some(value) => value,
            None if index < self.len => panic!("use of reclaimed {} {index}", self.name),
            None => panic!("{} {index} out of bounds ({})", self.name, self.len),
        }
    }
}

impl<T> std::ops::IndexMut<usize> for ReclaimableTable<T> {
    fn index_mut(&mut self, index: usize) -> &mut T {
        let (name, len) = (self.name, self.len);
        if index >= len {
            panic!("{name} {index} out of bounds ({len})");
        }
        self.get_mut(index)
            .unwrap_or_else(|| panic!("use of reclaimed {name} {index}"))
    }
}

/// A heap-allocated object with string-keyed properties.
///
/// The internal slots only some objects have (an ArrayBuffer's bytes, a
/// view, a Blob, a RegExp's source, a wrapper's primitive, class metadata, a
/// brand) are boxed: inline, their `None`s made every `{}` about 900 bytes,
/// against Node's ~130 (bd-9vouw.464).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HeapObject {
    /// Data properties in ECMAScript own-key order with deterministic lookup.
    pub properties: OrderedStringMap<Value>,
    /// Per-own-string-property IFC labels (bd-ojvo1). A missing entry denotes
    /// `Label::Public`, so this map stays sparse (only non-Public provenance is
    /// stored) and serialization/accounting are unchanged for the common case.
    /// Without this, a `Secret` value written to a property of a lower-labeled
    /// object would launder back out as the object's label on later reads.
    property_labels: OrderedStringMap<Label>,
    /// Own-property attributes that differ from the ordinary-assignment
    /// default `{writable, enumerable, configurable: true}` (ES2020 6.1.7.1).
    /// Sparse like `property_labels`: a missing entry is the default, so
    /// objects built by plain assignment carry no entries.
    property_attributes: BTreeMap<RuntimePropertyKey, PropertyAttributes>,
    /// Prototype link used by membership operators and constructor instances.
    pub prototype: Option<ObjectId>,
    /// Constructor function index that allocated this object via `Construct`.
    pub constructor_function: Option<u32>,
    /// Engine-private parent constructor slot, inaccessible to guest code.
    derived_constructor_parent: Option<Box<Value>>,
    /// IFC provenance paired with the private parent constructor slot.
    derived_constructor_parent_label: Option<Box<Label>>,
    /// Whether the owning function is a derived class constructor.
    is_derived_constructor: bool,
    /// Whether the owning function uses the implicit forwarding constructor.
    is_default_derived_constructor: bool,
    /// Engine-private ES2022 class field list: on a class's prototype object
    /// its instance fields, on its constructor's own-property object its
    /// static fields (consumed once they run). An internal array
    /// `[key0, initializer0, key1, initializer1, ...]` in declaration order,
    /// reachable only through this slot.
    class_fields: Option<Box<Value>>,
    /// The [[BooleanData]], [[NumberData]], [[StringData]], [[BigIntData]] or
    /// [[SymbolData]] of a primitive wrapper object (`Object(1)`,
    /// `new String('a')`; ES2020 19.3.4, 20.1.4, 21.1.4, 20.2.4, 19.4.4).
    /// Engine-private: guest code reaches it only through the prototype
    /// methods' thisXValue and the conversions.
    primitive_value: Option<Box<Value>>,
    /// The engine-assigned brand of a built-in or host object (`"Map"`,
    /// `"Date"`, `"ClientRequest"`, `"Intl.NumberFormat"`, ...): what its
    /// methods' receiver checks, member dispatch, Object.prototype.toString
    /// and inspect consult (bd-9vouw.150). Engine-private: it is not a
    /// property, so guest code can neither see nor forge it, and a guest
    /// `__type` property is ordinary data.
    brand: Option<Box<JsString>>,
    /// Whether this object was created as a true Array instance.
    pub is_array: bool,
    /// Cached dense length for arrays (None = sparse, compute from properties).
    pub cached_dense_length: Option<u32>,
    /// Optional ArrayBuffer backing-store bytes for JS-visible binary memory.
    pub array_buffer: Option<Box<ArrayBufferBacking>>,
    /// Optional fixed-length typed-array view over an ArrayBuffer backing store.
    pub typed_array: Option<Box<TypedArrayView>>,
    /// Optional fixed-length DataView over an ArrayBuffer backing store.
    pub data_view: Option<Box<DataViewView>>,
    /// Whether this object has been frozen via Object.freeze().
    pub is_frozen: bool,
    /// Private [[Extensible]] state; guest property names cannot forge it.
    is_non_extensible: bool,
    /// Whether this object is the engine-owned `import.meta` contract object.
    pub is_import_meta: bool,
    /// Whether a `None` `prototype` is an explicit null
    /// (`Object.create(null)`, `setPrototypeOf(o, null)`, `__proto__ = null`)
    /// rather than the unset default link to %Object.prototype% /
    /// %Array.prototype% (bd-9vouw.34).
    is_null_prototype: bool,
    /// ES2022 [[PrivateElements]]: private fields, methods and accessors,
    /// keyed by class private name. They are not properties: no reflection,
    /// enumeration, Proxy trap, prototype walk or integrity level
    /// (`Object.freeze`) reaches them.
    private_elements: BTreeMap<SymbolId, PrivateElement>,
    /// Keys of the virtual own properties a canonical builtin prototype
    /// supplies without storing them (its methods, `constructor`,
    /// @@iterator) that `delete` removed (bd-9vouw.93). They are
    /// configurable, so `delete Array.prototype.fill` must make them absent;
    /// the virtual lookups skip a key listed here. Empty on every other
    /// object.
    deleted_virtual_keys: BTreeSet<RuntimePropertyKey>,
    /// The bytes and type of a WHATWG Blob (bd-9vouw.226); `None` on every
    /// other object.
    blob: Option<Box<blob::BlobData>>,
    /// A RegExp's [[OriginalSource]] and [[OriginalFlags]] (bd-9vouw.150
    /// phase 2): engine-private, so guest properties named `source` or
    /// `flags` neither change nor reveal them, and reflection lists only
    /// `lastIndex`.
    regexp: Option<Box<RegExpSlots>>,
    /// A Date's [[DateValue]], independent of guest properties and integrity
    /// levels (ES2020 20.4.5). A boxed Number keeps ordinary objects small
    /// and preserves NaN exactly in execution seeds and serialized heaps.
    date_value: Option<Box<Float64>>,
}

/// A RegExp's pattern, escaped as `source` reads it back (bd-9vouw.243),
/// and its flags in canonical order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegExpSlots {
    pub source: String,
    pub flags: String,
}

/// One ES2022 PrivateElement (6.2.10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum PrivateElement {
    /// A private field and the IFC label of its value.
    Field { value: Value, label: Label },
    /// A private method: read-only.
    Method { function: Value },
    /// A private accessor; a missing half throws when used.
    Accessor {
        get: Option<Value>,
        set: Option<Value>,
    },
}

impl PrivateElement {
    fn values(&self) -> impl Iterator<Item = &Value> {
        let (first, second) = match self {
            Self::Field { value, .. } => (Some(value), None),
            Self::Method { function } => (Some(function), None),
            Self::Accessor { get, set } => (get.as_ref(), set.as_ref()),
        };
        first.into_iter().chain(second)
    }
}

/// Serialized form of one [[PrivateElements]] entry.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateElementWire {
    symbol_id: u32,
    element: PrivateElement,
}

/// The boolean attributes of an own property (ES2020 6.1.7.1). `writable` is
/// meaningless for accessor properties and is ignored there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PropertyAttributes {
    writable: bool,
    enumerable: bool,
    configurable: bool,
}

impl PropertyAttributes {
    /// Attributes of a property created by ordinary assignment.
    const DEFAULT: Self = Self {
        writable: true,
        enumerable: true,
        configurable: true,
    };
}

impl Default for PropertyAttributes {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Writable, configurable, not enumerable: builtin data properties such as
/// `Error.prototype.name` and an error's own `message` and `stack`.
const NON_ENUMERABLE_DATA_ATTRIBUTES: PropertyAttributes = PropertyAttributes {
    writable: true,
    enumerable: false,
    configurable: true,
};

/// Microtasks a drain runs between compactions of the queue's consumed
/// slots (bd-9vouw.71).
const MICROTASK_COMPACTION_INTERVAL: u32 = 1024;

/// Most compiled RegExp patterns one interpreter keeps for reuse.
const REGEXP_CACHE_ENTRIES: usize = 32;
/// Longest pattern source the RegExp cache keeps compiled. The compiled
/// limits below bound what the cache holds; this only keeps a lookup (a scan
/// comparing sources) cheap. At 256 bytes, a module-level pattern like
/// semver's (565 bytes) recompiled on every `test`, 18 times slower than a
/// cached one (bd-9vouw.183).
const REGEXP_CACHE_MAX_PATTERN_BYTES: usize = 16 * 1024;
/// Compiled-program limit for a cached RegExp. A pattern that needs more
/// compiles under the default limits and is not kept, so the cache holds at
/// most about `REGEXP_CACHE_ENTRIES` times this plus the DFA limit below.
const REGEXP_CACHE_MAX_PROGRAM_BYTES: usize = 1024 * 1024;
/// Lazy-DFA transition cache limit for a cached RegExp. It bounds only how
/// much of the DFA is kept; matching falls back to other engines past it.
const REGEXP_CACHE_MAX_DFA_BYTES: usize = 512 * 1024;
/// Backtracking programs kept in the cache stay below this many
/// instructions (a few hundred KiB at most).
const REGEXP_CACHE_MAX_BACKTRACK_INSTRUCTIONS: usize = 4096;

/// Not writable, not enumerable, configurable: a function's own `length` and
/// `name` (ES2020 9.2.4 SetFunctionLength, 9.2.11 SetFunctionName, 17 for
/// built-ins; bd-9vouw.17).
const FUNCTION_NAME_LENGTH_ATTRIBUTES: PropertyAttributes = PropertyAttributes {
    writable: false,
    enumerable: false,
    configurable: true,
};

/// Not writable, not enumerable, not configurable: the value properties of
/// the builtin namespaces and constructors (`Math.PI`, ES2020 20.2.1).
const READ_ONLY_VALUE_ATTRIBUTES: PropertyAttributes = PropertyAttributes {
    writable: false,
    enumerable: false,
    configurable: false,
};

/// `RegExp.prototype`'s symbol-keyed methods (ES2020 21.2.5.6-11): the key a
/// [`BuiltinFunctionKind::RegExpSymbolMethod`] carries, and its `name`.
const REGEXP_SYMBOL_METHODS: [(&str, &str); 5] = [
    ("@@match", "[Symbol.match]"),
    ("@@matchAll", "[Symbol.matchAll]"),
    ("@@replace", "[Symbol.replace]"),
    ("@@search", "[Symbol.search]"),
    ("@@split", "[Symbol.split]"),
];

/// The [`REGEXP_SYMBOL_METHODS`] key of a well-known symbol, if it names one.
fn regexp_symbol_method_key(symbol: SymbolId) -> Option<&'static str> {
    [
        (WellKnownSymbol::Match, "@@match"),
        (WellKnownSymbol::MatchAll, "@@matchAll"),
        (WellKnownSymbol::Replace, "@@replace"),
        (WellKnownSymbol::Search, "@@search"),
        (WellKnownSymbol::Split, "@@split"),
    ]
    .into_iter()
    .find(|(well_known, _)| well_known.id() == symbol)
    .map(|(_, key)| key)
}

/// Prototypes that carry `name` and `message` (ES2020 19.5.3, 19.5.6.3;
/// ES2021 20.5.7.3 for AggregateError).
const ERROR_PROTOTYPE_NAMES: [&str; 8] = [
    "Error",
    "TypeError",
    "RangeError",
    "ReferenceError",
    "SyntaxError",
    "EvalError",
    "URIError",
    "AggregateError",
];

/// What [[Set]] of a typed array does with a canonical numeric key
/// (`typed_array_set_runtime_property`).
enum TypedArraySetOutcome {
    /// The set is complete with this result.
    Done(bool),
    /// A valid index through another receiver: OrdinarySet defines the
    /// property on the receiver without walking further up the chain.
    DefineOnReceiver,
}

/// A property descriptor as read by ES2020 6.2.5.5 ToPropertyDescriptor.
/// `None` marks an absent field; a present `get`/`set` holds a callable or
/// `undefined`.
#[derive(Debug, Clone, Default)]
struct PropertyDescriptorFields {
    value: Option<Value>,
    writable: Option<bool>,
    get: Option<Value>,
    set: Option<Value>,
    enumerable: Option<bool>,
    configurable: Option<bool>,
}

impl PropertyDescriptorFields {
    fn is_accessor(&self) -> bool {
        self.get.is_some() || self.set.is_some()
    }

    fn is_data(&self) -> bool {
        self.value.is_some() || self.writable.is_some()
    }
}

/// Serialized form of one non-default attribute entry. Exactly one of `key`
/// (String-keyed) and `symbol_id` (Symbol-keyed) is present.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PropertyAttributesWire {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key: Option<JsString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    symbol_id: Option<u32>,
    writable: bool,
    enumerable: bool,
    configurable: bool,
}

/// One key of [`HeapObject::deleted_virtual_keys`]: a String key or a
/// nonzero Symbol id, exactly one.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PropertyKeyWire {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key: Option<JsString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    symbol_id: Option<u32>,
}

struct HeapSymbolPropertyRef<'a> {
    symbol_id: SymbolId,
    property: &'a BaselineSymbolProperty<Value>,
}

impl Serialize for HeapSymbolPropertyRef<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct as _;

        match self.property {
            BaselineSymbolProperty::Data(value) => {
                let mut record = serializer.serialize_struct("SymbolProperty", 3)?;
                record.serialize_field("symbol_id", &self.symbol_id.0)?;
                record.serialize_field("kind", "data")?;
                record.serialize_field("value", value)?;
                record.end()
            }
            BaselineSymbolProperty::Accessor { get, set } => {
                let mut record = serializer.serialize_struct("SymbolProperty", 4)?;
                record.serialize_field("symbol_id", &self.symbol_id.0)?;
                record.serialize_field("kind", "accessor")?;
                record.serialize_field("get", get)?;
                record.serialize_field("set", set)?;
                record.end()
            }
        }
    }
}

impl Serialize for HeapObject {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct as _;

        let symbol_properties = self
            .properties
            .baseline_symbol_properties()
            .map(|(symbol_id, property)| HeapSymbolPropertyRef {
                symbol_id: engine_symbol_id(symbol_id),
                property,
            })
            .collect::<Vec<_>>();
        let has_constructor_metadata = self.is_derived_constructor
            || self.is_default_derived_constructor
            || self.derived_constructor_parent.is_some()
            || self.derived_constructor_parent_label.is_some();
        let mut object = serializer.serialize_struct(
            "HeapObject",
            10 + usize::from(self.is_non_extensible)
                + usize::from(self.is_null_prototype)
                + usize::from(!symbol_properties.is_empty())
                + usize::from(!self.property_labels.is_empty())
                + usize::from(!self.property_attributes.is_empty())
                + usize::from(self.class_fields.is_some())
                + usize::from(self.primitive_value.is_some())
                + usize::from(self.brand.is_some())
                + usize::from(!self.private_elements.is_empty())
                + usize::from(!self.deleted_virtual_keys.is_empty())
                + usize::from(self.blob.is_some())
                + usize::from(self.regexp.is_some())
                + usize::from(self.date_value.is_some())
                + if has_constructor_metadata { 4 } else { 0 },
        )?;
        object.serialize_field("properties", &self.properties)?;
        object.serialize_field("prototype", &self.prototype)?;
        object.serialize_field("constructor_function", &self.constructor_function)?;
        object.serialize_field("is_array", &self.is_array)?;
        object.serialize_field("cached_dense_length", &self.cached_dense_length)?;
        object.serialize_field("array_buffer", &self.array_buffer)?;
        object.serialize_field("typed_array", &self.typed_array)?;
        object.serialize_field("data_view", &self.data_view)?;
        object.serialize_field("is_frozen", &self.is_frozen)?;
        if self.is_non_extensible {
            object.serialize_field("is_non_extensible", &true)?;
        }
        if self.is_null_prototype {
            object.serialize_field("is_null_prototype", &true)?;
        }
        object.serialize_field("is_import_meta", &self.is_import_meta)?;
        if has_constructor_metadata {
            object.serialize_field(
                "derived_constructor_parent",
                &self.derived_constructor_parent,
            )?;
            object.serialize_field(
                "derived_constructor_parent_label",
                &self.derived_constructor_parent_label,
            )?;
            object.serialize_field("is_derived_constructor", &self.is_derived_constructor)?;
            object.serialize_field(
                "is_default_derived_constructor",
                &self.is_default_derived_constructor,
            )?;
        }
        if let Some(fields) = &self.class_fields {
            object.serialize_field("class_fields", fields)?;
        }
        if let Some(value) = &self.primitive_value {
            object.serialize_field("primitive_value", value)?;
        }
        if let Some(brand) = &self.brand {
            object.serialize_field("brand", brand)?;
        }
        if let Some(blob) = &self.blob {
            object.serialize_field("blob", blob)?;
        }
        if let Some(regexp) = &self.regexp {
            object.serialize_field("regexp", regexp)?;
        }
        if let Some(date_value) = &self.date_value {
            object.serialize_field("date_value", date_value)?;
        }
        if !self.private_elements.is_empty() {
            let elements = self
                .private_elements
                .iter()
                .map(|(symbol, element)| PrivateElementWire {
                    symbol_id: symbol.0,
                    element: element.clone(),
                })
                .collect::<Vec<_>>();
            object.serialize_field("private_elements", &elements)?;
        }
        if !self.property_labels.is_empty() {
            object.serialize_field("property_labels", &self.property_labels)?;
        }
        if !self.property_attributes.is_empty() {
            let attributes = self
                .property_attributes
                .iter()
                .map(|(key, attributes)| {
                    let (key, symbol_id) = match key {
                        RuntimePropertyKey::String(key) => (Some(key.clone()), None),
                        RuntimePropertyKey::Symbol(symbol) => (None, Some(symbol.0)),
                    };
                    PropertyAttributesWire {
                        key,
                        symbol_id,
                        writable: attributes.writable,
                        enumerable: attributes.enumerable,
                        configurable: attributes.configurable,
                    }
                })
                .collect::<Vec<_>>();
            object.serialize_field("property_attributes", &attributes)?;
        }
        if !symbol_properties.is_empty() {
            object.serialize_field("symbol_properties", &symbol_properties)?;
        }
        if !self.deleted_virtual_keys.is_empty() {
            let keys = self
                .deleted_virtual_keys
                .iter()
                .map(|key| match key {
                    RuntimePropertyKey::String(key) => PropertyKeyWire {
                        key: Some(key.clone()),
                        symbol_id: None,
                    },
                    RuntimePropertyKey::Symbol(symbol) => PropertyKeyWire {
                        key: None,
                        symbol_id: Some(symbol.0),
                    },
                })
                .collect::<Vec<_>>();
            object.serialize_field("deleted_virtual_keys", &keys)?;
        }
        object.end()
    }
}

impl<'de> Deserialize<'de> for HeapObject {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;

        #[derive(Deserialize)]
        struct HeapObjectWire {
            properties: OrderedStringMap<Value>,
            prototype: Option<ObjectId>,
            constructor_function: Option<u32>,
            is_array: bool,
            cached_dense_length: Option<u32>,
            array_buffer: Option<Box<ArrayBufferBacking>>,
            typed_array: Option<Box<TypedArrayView>>,
            data_view: Option<Box<DataViewView>>,
            is_frozen: bool,
            #[serde(default)]
            is_non_extensible: bool,
            #[serde(default)]
            is_null_prototype: bool,
            #[serde(default)]
            is_import_meta: bool,
            #[serde(default)]
            derived_constructor_parent: Option<Box<Value>>,
            #[serde(default)]
            derived_constructor_parent_label: Option<Box<Label>>,
            #[serde(default)]
            is_derived_constructor: bool,
            #[serde(default)]
            is_default_derived_constructor: bool,
            #[serde(default)]
            class_fields: Option<Box<Value>>,
            #[serde(default)]
            primitive_value: Option<Box<Value>>,
            #[serde(default)]
            brand: Option<Box<JsString>>,
            #[serde(default)]
            private_elements: Vec<PrivateElementWire>,
            #[serde(default)]
            property_labels: OrderedStringMap<Label>,
            #[serde(default)]
            property_attributes: Vec<PropertyAttributesWire>,
            #[serde(default)]
            symbol_properties: Vec<HeapSymbolPropertyWire>,
            #[serde(default)]
            deleted_virtual_keys: Vec<PropertyKeyWire>,
            #[serde(default)]
            blob: Option<Box<blob::BlobData>>,
            #[serde(default)]
            regexp: Option<Box<RegExpSlots>>,
            #[serde(default)]
            date_value: Option<Box<Float64>>,
        }

        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct HeapSymbolPropertyWire {
            symbol_id: u32,
            kind: String,
            #[serde(default, deserialize_with = "deserialize_present_value")]
            value: Option<PresentValue<Value>>,
            #[serde(default, deserialize_with = "deserialize_present_nullable")]
            get: Option<PresentNullable<Value>>,
            #[serde(default, deserialize_with = "deserialize_present_nullable")]
            set: Option<PresentNullable<Value>>,
        }

        let wire = HeapObjectWire::deserialize(deserializer)?;
        let has_parent = wire.derived_constructor_parent.is_some();
        let has_parent_label = wire.derived_constructor_parent_label.is_some();
        if has_parent != has_parent_label {
            return Err(D::Error::custom(
                "derived constructor parent and label must be present together",
            ));
        }
        if wire.is_derived_constructor != has_parent {
            return Err(D::Error::custom(
                "derived constructor metadata must include parent, label, and derived flag",
            ));
        }
        if wire.is_default_derived_constructor && !wire.is_derived_constructor {
            return Err(D::Error::custom(
                "default derived constructor flag requires derived constructor metadata",
            ));
        }
        let mut property_attributes = BTreeMap::new();
        for record in wire.property_attributes {
            let key = match (record.key, record.symbol_id) {
                (Some(key), None) => RuntimePropertyKey::String(key),
                (None, Some(symbol_id)) if symbol_id != 0 => {
                    RuntimePropertyKey::Symbol(SymbolId(symbol_id))
                }
                _ => {
                    return Err(D::Error::custom(
                        "property attributes need exactly one String key or nonzero Symbol id",
                    ));
                }
            };
            let attributes = PropertyAttributes {
                writable: record.writable,
                enumerable: record.enumerable,
                configurable: record.configurable,
            };
            if attributes == PropertyAttributes::DEFAULT
                || property_attributes.insert(key, attributes).is_some()
            {
                return Err(D::Error::custom(
                    "property attributes must be sparse and unique per key",
                ));
            }
        }
        let mut deleted_virtual_keys = BTreeSet::new();
        for record in wire.deleted_virtual_keys {
            let key = match (record.key, record.symbol_id) {
                (Some(key), None) => RuntimePropertyKey::String(key),
                (None, Some(symbol_id)) if symbol_id != 0 => {
                    RuntimePropertyKey::Symbol(SymbolId(symbol_id))
                }
                _ => {
                    return Err(D::Error::custom(
                        "a deleted virtual key needs exactly one String key or nonzero Symbol id",
                    ));
                }
            };
            if !deleted_virtual_keys.insert(key) {
                return Err(D::Error::custom("deleted virtual keys must be unique"));
            }
        }
        let mut private_elements = BTreeMap::new();
        for record in wire.private_elements {
            let well_formed = record.symbol_id != 0
                && !matches!(
                    record.element,
                    PrivateElement::Accessor {
                        get: None,
                        set: None
                    }
                );
            if !well_formed
                || private_elements
                    .insert(SymbolId(record.symbol_id), record.element)
                    .is_some()
            {
                return Err(D::Error::custom(
                    "private elements need unique nonzero names and an accessor half",
                ));
            }
        }
        let mut object = Self {
            properties: wire.properties,
            property_labels: wire.property_labels,
            property_attributes,
            prototype: wire.prototype,
            constructor_function: wire.constructor_function,
            is_array: wire.is_array,
            cached_dense_length: wire.cached_dense_length,
            array_buffer: wire.array_buffer,
            typed_array: wire.typed_array,
            data_view: wire.data_view,
            is_frozen: wire.is_frozen,
            is_non_extensible: wire.is_non_extensible,
            is_null_prototype: wire.is_null_prototype && wire.prototype.is_none(),
            is_import_meta: wire.is_import_meta,
            derived_constructor_parent: wire.derived_constructor_parent,
            derived_constructor_parent_label: wire.derived_constructor_parent_label,
            is_derived_constructor: wire.is_derived_constructor,
            is_default_derived_constructor: wire.is_default_derived_constructor,
            class_fields: wire.class_fields,
            primitive_value: wire.primitive_value,
            brand: wire.brand,
            private_elements,
            deleted_virtual_keys,
            blob: wire.blob,
            regexp: wire.regexp,
            date_value: wire.date_value,
        };
        for record in wire.symbol_properties {
            let symbol = SymbolId(record.symbol_id);
            if symbol.0 == 0 {
                return Err(D::Error::custom("Symbol property id must be nonzero"));
            }
            let property = match record.kind.as_str() {
                "data" => {
                    if record.get.is_some() || record.set.is_some() {
                        return Err(D::Error::custom(
                            "data Symbol property forbids accessor endpoints",
                        ));
                    }
                    BaselineSymbolProperty::Data(
                        record
                            .value
                            .ok_or_else(|| D::Error::custom("data Symbol property requires value"))?
                            .0,
                    )
                }
                "accessor" => {
                    if record.value.is_some() {
                        return Err(D::Error::custom(
                            "accessor Symbol property forbids data value",
                        ));
                    }
                    BaselineSymbolProperty::Accessor {
                        get: record
                            .get
                            .ok_or_else(|| {
                                D::Error::custom("accessor Symbol property requires get")
                            })?
                            .0,
                        set: record
                            .set
                            .ok_or_else(|| {
                                D::Error::custom("accessor Symbol property requires set")
                            })?
                            .0,
                    }
                }
                _ => return Err(D::Error::custom("unknown Symbol property kind")),
            };
            if object
                .properties
                .insert_baseline_symbol_property(core_symbol_id(symbol), property)
                .is_some()
            {
                return Err(D::Error::custom("duplicate Symbol property id"));
            }
        }
        if object
            .property_attributes
            .keys()
            .any(|key| !object.contains_own_runtime_property(key))
        {
            return Err(D::Error::custom(
                "property attributes must name an own property",
            ));
        }
        Ok(object)
    }
}

pub(crate) fn heap_object_contains_symbols(object: &HeapObject) -> bool {
    !object.properties.baseline_symbol_key_order().is_empty()
        || !object.private_elements.is_empty()
        || object
            .deleted_virtual_keys
            .iter()
            .any(|key| matches!(key, RuntimePropertyKey::Symbol(_)))
        || object
            .derived_constructor_parent
            .as_deref()
            .is_some_and(value_contains_symbol)
        || object
            .class_fields
            .as_deref()
            .is_some_and(value_contains_symbol)
        || object
            .primitive_value
            .as_deref()
            .is_some_and(value_contains_symbol)
        || object
            .properties
            .all_data_values()
            .any(value_contains_symbol)
        || object
            .properties
            .baseline_symbol_properties()
            .any(|(_, property)| match property {
                BaselineSymbolProperty::Data(value) => value_contains_symbol(value),
                BaselineSymbolProperty::Accessor { get, set } => {
                    get.as_ref().is_some_and(value_contains_symbol)
                        || set.as_ref().is_some_and(value_contains_symbol)
                }
            })
}

pub(crate) fn value_contains_symbol(value: &Value) -> bool {
    let mut stack = vec![value];
    let mut visited = BTreeSet::new();
    while let Some(value) = stack.pop() {
        match value {
            Value::Symbol(_) => return true,
            Value::Accessor { get, set } => {
                for endpoint in [get.as_deref(), set.as_deref()].into_iter().flatten() {
                    if visited.insert(endpoint as *const Value) {
                        stack.push(endpoint);
                    }
                }
            }
            _ => {}
        }
    }
    false
}

fn validate_symbol_value(state: &RuntimeSymbolState, value: &Value) -> Result<(), String> {
    match value {
        Value::Symbol(id) if !state.contains(*id) => {
            return Err(format!("unresolved Symbol id {}", id.0));
        }
        Value::Symbol(_) => return Ok(()),
        Value::Accessor { .. } => {}
        _ => return Ok(()),
    }

    let mut stack = vec![value];
    let mut visited = BTreeSet::new();
    while let Some(value) = stack.pop() {
        match value {
            Value::Symbol(id) if !state.contains(*id) => {
                return Err(format!("unresolved Symbol id {}", id.0));
            }
            Value::Accessor { get, set } => {
                for endpoint in [get.as_deref(), set.as_deref()].into_iter().flatten() {
                    if visited.insert(endpoint as *const Value) {
                        stack.push(endpoint);
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_heap_symbol_references(
    state: &RuntimeSymbolState,
    object: &HeapObject,
) -> Result<(), String> {
    if let Some(parent) = &object.derived_constructor_parent {
        validate_symbol_value(state, parent)?;
    }
    if let Some(fields) = &object.class_fields {
        validate_symbol_value(state, fields)?;
    }
    if let Some(value) = &object.primitive_value {
        validate_symbol_value(state, value)?;
    }
    for value in object.properties.all_data_values() {
        validate_symbol_value(state, value)?;
    }
    for (id, property) in object.properties.baseline_symbol_properties() {
        let id = engine_symbol_id(id);
        if !state.contains(id) {
            return Err(format!("unresolved Symbol property id {}", id.0));
        }
        match property {
            BaselineSymbolProperty::Data(value) => validate_symbol_value(state, value)?,
            BaselineSymbolProperty::Accessor { get, set } => {
                if let Some(getter) = get {
                    validate_symbol_value(state, getter)?;
                }
                if let Some(setter) = set {
                    validate_symbol_value(state, setter)?;
                }
            }
        }
    }
    for (name, element) in &object.private_elements {
        if !state.is_class_private_name(*name) {
            return Err(format!(
                "private element keyed by non-private-name Symbol {}",
                name.0
            ));
        }
        for value in element.values() {
            validate_symbol_value(state, value)?;
        }
    }
    Ok(())
}

impl HeapObject {
    fn extensible(&self) -> bool {
        !self.is_non_extensible && !self.is_frozen
    }

    /// The engine-assigned brand (bd-9vouw.150): `Some("Map")` for a Map,
    /// `None` for an ordinary object whatever its properties say.
    fn brand(&self) -> Option<&str> {
        self.brand.as_deref().map(|brand| &**brand)
    }

    fn date_time(&self) -> Option<f64> {
        self.date_value.as_deref().map(|value| value.inner())
    }

    /// Effective attributes of the own property `key` (assumed present). A
    /// frozen object's properties are all non-configurable and non-writable.
    /// An array's `length` is { writable, not enumerable, not configurable }
    /// (ES2020 9.4.2.2 ArrayCreate) unless an explicit entry records
    /// otherwise, so for-in, Object.keys, descriptors and delete agree.
    fn own_property_attributes(&self, key: &RuntimePropertyKey) -> PropertyAttributes {
        let mut attributes = self.property_attributes.get(key).copied().unwrap_or_else(|| {
            let mut attributes = PropertyAttributes::default();
            if self.is_array
                && matches!(key, RuntimePropertyKey::String(name) if name.as_str() == Some("length"))
            {
                attributes.enumerable = false;
                attributes.configurable = false;
            }
            attributes
        });
        if self.is_frozen {
            attributes.writable = false;
            attributes.configurable = false;
        }
        attributes
    }

    pub fn new() -> Self {
        Self::default()
    }

    fn own_runtime_property_descriptor(
        &self,
        key: &RuntimePropertyKey,
    ) -> Option<BaselineSymbolProperty<Value>> {
        match key {
            RuntimePropertyKey::String(key) => {
                self.properties.get_exact(key).cloned().map(|value| {
                    if let Value::Accessor { get, set } = value {
                        BaselineSymbolProperty::Accessor {
                            get: get.map(|value| value.as_ref().clone()),
                            set: set.map(|value| value.as_ref().clone()),
                        }
                    } else {
                        BaselineSymbolProperty::Data(value)
                    }
                })
            }
            RuntimePropertyKey::Symbol(symbol) => self
                .properties
                .baseline_symbol_property(core_symbol_id(*symbol))
                .cloned(),
        }
    }

    fn own_runtime_property_value(&self, key: &RuntimePropertyKey) -> Option<Value> {
        self.own_runtime_property_descriptor(key)
            .map(|property| match property {
                BaselineSymbolProperty::Data(value) => value,
                BaselineSymbolProperty::Accessor { get, set } => Value::Accessor {
                    get: get.map(Arc::new),
                    set: set.map(Arc::new),
                },
            })
    }

    fn contains_own_runtime_property(&self, key: &RuntimePropertyKey) -> bool {
        match key {
            RuntimePropertyKey::String(key) => self.properties.contains_exact_key(key),
            RuntimePropertyKey::Symbol(symbol) => self
                .properties
                .baseline_symbol_property(core_symbol_id(*symbol))
                .is_some(),
        }
    }

    fn own_runtime_property_keys(&self) -> Vec<RuntimePropertyKey> {
        self.properties
            .exact_keys()
            .into_iter()
            .map(RuntimePropertyKey::String)
            .chain(
                self.properties
                    .baseline_symbol_key_order()
                    .iter()
                    .copied()
                    .map(engine_symbol_id)
                    .map(RuntimePropertyKey::Symbol),
            )
            .collect()
    }
}

/// Compat alias. Several recently-landed Date/Error/Map/Set/Promise builtin
/// blocks refer to `Object` (the ES spec name) rather than `HeapObject`
/// (the internal struct). Alias so they keep compiling.
pub type Object = HeapObject;

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeForInState {
    object_id: ObjectId,
    keys: Vec<JsString>,
    next_index: usize,
    deleted_keys: BTreeSet<JsString>,
    done: bool,
    closed: bool,
    trace_index: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeForOfState {
    values: Vec<Value>,
    next_index: usize,
    /// Array iterators retain the source, not an eager copy of its elements.
    /// Each next observes the current length and performs the indexed Get.
    array: Option<RuntimeArrayIterator>,
    /// Typed-array iterators are lazy. Eagerly materializing one `Value` per
    /// byte amplified a bounded Buffer into an unmetered host allocation.
    typed_array: Option<RuntimeTypedArrayIterator>,
    /// Map and Set iterators read the live entry list (bd-9vouw.131).
    collection: Option<RuntimeCollectionIterator>,
    iterator_receiver: Option<Value>,
    next_method: Option<Value>,
    /// bd-suwvw: a `require('timers/promises').setInterval` iterable —
    /// `(delay_ms, yielded value)`. Each advance ticks the deterministic
    /// virtual clock by `delay_ms` and yields the value; the iterator never
    /// completes on its own (the loop body `break`s out).
    timers_interval: Option<(u64, Value)>,
    done: bool,
    closed: bool,
    return_called: bool,
    trace_index: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeForOfInit {
    values: Vec<Value>,
    array: Option<RuntimeArrayIterator>,
    typed_array: Option<RuntimeTypedArrayIterator>,
    collection: Option<RuntimeCollectionIterator>,
    iterator_receiver: Option<Value>,
    next_method: Option<Value>,
    timers_interval: Option<(u64, Value)>,
}

impl RuntimeForOfInit {
    fn from_values(values: Vec<Value>) -> Self {
        Self {
            values,
            array: None,
            typed_array: None,
            collection: None,
            iterator_receiver: None,
            next_method: None,
            timers_interval: None,
        }
    }

    /// Steps `object_id` as the intrinsic ArrayIterator's `next` would: the
    /// live `length`, then the indexed Get (bd-9vouw.70).
    fn from_array(object_id: ObjectId) -> Self {
        Self {
            array: Some(RuntimeArrayIterator {
                object_id,
                kind: RuntimeTypedArrayIteratorKind::Values,
            }),
            ..Self::from_values(Vec::new())
        }
    }

    /// The live entries of a Map (`[key, value]` pairs) or Set (values),
    /// as their @@iterator would step them (bd-9vouw.131).
    fn from_collection(iterator: RuntimeCollectionIterator) -> Self {
        Self {
            collection: Some(iterator),
            ..Self::from_values(Vec::new())
        }
    }

    #[cfg(test)]
    fn from_custom(iterator_object: ObjectId, next_method: Value) -> Self {
        Self {
            values: Vec::new(),
            array: None,
            typed_array: None,
            collection: None,
            iterator_receiver: Some(Value::Object(iterator_object)),
            next_method: Some(next_method),
            timers_interval: None,
        }
    }

    fn from_receiver(receiver: Value, next_method: Value) -> Self {
        Self {
            values: Vec::new(),
            array: None,
            typed_array: None,
            collection: None,
            iterator_receiver: Some(receiver),
            next_method: Some(next_method),
            timers_interval: None,
        }
    }

    fn from_existing(handle: u32) -> Self {
        // A consumption record owns its Done/close state; the iterator object
        // it borrows must remain resumable when it has no return method.
        Self::from_receiver(
            Value::Iterator(handle),
            Value::BuiltinFunction(BuiltinFunction::iterator_next(handle)),
        )
    }

    /// bd-suwvw: see [`RuntimeForOfState::timers_interval`].
    fn from_timers_interval(delay_ms: u64, value: Value) -> Self {
        Self {
            values: Vec::new(),
            array: None,
            typed_array: None,
            collection: None,
            iterator_receiver: None,
            next_method: None,
            timers_interval: Some((delay_ms, value)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeTypedArrayIteratorKind {
    Entries,
    Keys,
    Values,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeTypedArrayIterator {
    view: TypedArrayView,
    kind: RuntimeTypedArrayIteratorKind,
    /// The typed array, whose current view each step reads (bd-9vouw.256).
    object: ObjectId,
}

/// The prototype and own-property owner ids of one module's functions,
/// digested once per module header (bd-9vouw.124): `new F()` and every
/// function property read took one to three SHA-256 digests.
#[derive(Debug, Clone, Copy)]
struct PrototypeOwnerIds {
    function: ContentHash,
    closure: ContentHash,
    /// [`InterpreterCore::function_own_property_owner`] of kinds 0-4: the
    /// IR3 function over `function`, the closure kinds over `closure`.
    own_property: [ContentHash; 5],
}

/// Module headers [`InterpreterCore::prototype_owner_ids`] remembers; the
/// oldest goes first.
const PROTOTYPE_OWNER_MEMO_ENTRIES: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeArrayIterator {
    object_id: ObjectId,
    // Arrays and typed arrays expose the same keys/values/entries projections.
    kind: RuntimeTypedArrayIteratorKind,
}

/// A Map or Set iterator (ES2020 23.1.5, 23.2.5) over the live entry list of
/// its collection's storage object (bd-9vouw.131): the state's `next_index`
/// is a position in the storage's insertion order, which
/// `collection_delete` and `collection_clear` move back for every live
/// iterator registered in `collection_iterators`, so entries added while
/// iterating are visited and deleted ones are not.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeCollectionIterator {
    collection: ObjectId,
    storage: ObjectId,
    is_map: bool,
    kind: RuntimeTypedArrayIteratorKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RuntimeIteratorState {
    ForIn(RuntimeForInState),
    ForOf(RuntimeForOfState),
}

// ---------------------------------------------------------------------------
// Module runtime state (RC-1.13)
// ---------------------------------------------------------------------------

/// The host operation that requested a filesystem module. Source-delivered
/// records carry their syntax explicitly and do not use filename inference.
#[derive(Clone, Copy)]
enum ModuleLoadKind<'a> {
    Require,
    Import(&'a ImportAttributes),
    DynamicImport,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ModuleRuntimeStatus {
    Evaluating,
    /// Evaluation reached either this module's top-level await or an imported
    /// module that is still evaluating asynchronously. The executable program
    /// and suspended activation are retained by the module record until its
    /// evaluation Promise settles (bd-yn3lv).
    AsyncEvaluating,
    Evaluated,
    Failed(String),
}

/// How `export * from m` (bd-332pq) holds one of the module's export names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StarExportOrigin {
    /// One star source provides the name.
    Provided,
    /// Star sources provide different values: ES2020 ResolveExport finds the
    /// name ambiguous, so the module does not export it.
    Ambiguous,
}

#[derive(Debug, Clone)]
struct ModuleRuntimeRecord {
    status: ModuleRuntimeStatus,
    namespace_object: ObjectId,
    /// One stable import.meta object per module, retained for the realm.
    import_meta_object: Option<ObjectId>,
    exports: BTreeMap<JsString, Value>,
    /// Export names that came from `export * from` rather than this module's
    /// own export declarations (which always win).
    star_exports: BTreeMap<JsString, StarExportOrigin>,
    /// The module's static flow label ceiling once it is lowered: every value
    /// it can produce is at most this label (bd-j8f7q import contracts).
    flow_label_ceiling: Option<Label>,
    /// Canonical source record pinned before evaluation by an installed
    /// resolver. Repeated loads must authenticate this same record.
    resolved_source_hash: Option<ContentHash>,
    /// Importers' binding cells for each export name (bd-1lsy.4.10.1). Every
    /// publication of the export writes them, so an import is a live view of
    /// the exporting module's binding; a cell whose importer is gone drops
    /// out at the next publication.
    import_bindings: BTreeMap<JsString, Vec<Weak<RefCell<ScopeBindingState>>>>,
    /// Modules that `export * from` this one (bd-1lsy.4.10.1): a publication
    /// of a name they still re-export publishes it from them too.
    star_reexporters: BTreeSet<String>,
    cjs_module_object: Option<ObjectId>,
    /// The executable program that owns every closure created while this
    /// module is evaluated. Imported closures carry only an index into this
    /// program; retaining one shared `Arc` prevents that index from being
    /// reinterpreted against the importing module's function table.
    compiled_module: Option<Arc<Ir3Module>>,
    /// Promise representing completion of this module's async evaluation.
    evaluation_promise: Option<crate::promise_model::PromiseHandle>,
    /// Owned activation parked while an imported module is asynchronously
    /// evaluating. Entry-module execution remains installed in the core.
    async_execution: Option<ModuleExecutionSnapshot>,
}

#[derive(Clone)]
struct InstalledModuleResolver {
    resolver: ExecutionModuleResolver,
    entry_hash: ContentHash,
    context: ResolutionContext,
}

/// Realm-persistent dynamic-code artifacts owned by one immutable module
/// program. The owner key in [`ModuleState::generated_function_stores`] is the
/// canonical IR3 content hash of that program; keeping the same identity here
/// makes corruption and stale-handle checks fail closed at dispatch.
#[derive(Debug, Clone)]
struct GeneratedFunctionStore {
    /// Top-level realm generation that owns this store. A store from an older
    /// execution must never authenticate a handle after realm replacement,
    /// even when the same module and generated source are recreated.
    realm_generation: u64,
    owner_program_id: ContentHash,
    owner_specifier: String,
    owner_program: Arc<Ir3Module>,
    next_construction_ordinal: u64,
    artifacts: BTreeMap<ContentHash, GeneratedFunctionArtifact>,
}

#[derive(Debug, Clone, Default)]
struct ModuleState {
    modules: BTreeMap<String, ModuleRuntimeRecord>,
    /// Memory charged for retained module programs and their registry keys.
    /// The heap-resident namespace objects and exported values are accounted
    /// by their ordinary heap/register owners.
    retained_program_bytes: u64,
    /// Dynamic `Function` artifacts are realm-owned executable programs, not
    /// activation-local scratch. This owner-scoped registry survives module,
    /// callback, generator, and async execution snapshots.
    generated_function_stores: BTreeMap<ContentHash, GeneratedFunctionStore>,
    /// Cached logical charge for `generated_function_stores`.
    retained_generated_function_bytes: u64,
    /// Module bindings that back exports (bd-1lsy.4.10.1), indexed by their
    /// cells' `live_export`: a write to one republishes its exports.
    live_exports: Vec<LiveExport>,
}

impl ModuleState {
    fn new() -> Self {
        Self {
            modules: BTreeMap::new(),
            retained_program_bytes: 0,
            generated_function_stores: BTreeMap::new(),
            retained_generated_function_bytes: 0,
            live_exports: Vec::new(),
        }
    }
}

/// A module's scope binding and the exports it is the local binding of:
/// `(module specifier, export name)` pairs (bd-1lsy.4.10.1).
#[derive(Debug, Clone)]
struct LiveExport {
    cell: Rc<RefCell<ScopeBindingState>>,
    exports: Vec<(String, JsString)>,
}

/// Whose publication of an export it is (bd-1lsy.4.10.1): the module's own
/// export (which wins over a star re-export of the name), or a source
/// module's value reaching a module that `export * from` it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExportPublication {
    Own,
    Star,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CjsModuleContext {
    module_object: ObjectId,
    exports_object: ObjectId,
    module_specifier: String,
}

/// Deterministic, content-addressed provenance for a function produced by the
/// `Function` constructor (bd-8enww.3.4 / YTBG-C4). BotGuard-style generated
/// code is intentionally adversarial, so every artifact carries an auditable
/// identity derived from its construction site and source content — distilled
/// to hashes rather than retaining the (potentially hostile) raw source text,
/// mirroring the `hostcall_arguments_hash` posture of not persisting raw values.
#[derive(Debug, Clone, PartialEq, Eq)]
struct GeneratedFunctionProvenance {
    /// Stable synthetic source id (`genfn:<16 hex>`), a pure function of the
    /// construction-site label and the length-prefixed parameter/body source.
    /// Identical (site, source) always yields the same id, so the audit trail
    /// is content-addressed and re-derivable across runs.
    source_id: String,
    /// Hex SHA-256 of the full generated source text.
    source_hash: String,
    /// Hex SHA-256 of the parameter source alone.
    parameter_hash: String,
    /// Construction-site label: the module specifier active when the artifact
    /// was constructed (e.g. `<eval>` for top-level dynamic construction).
    construction_site: String,
}

#[derive(Debug, Clone)]
struct GeneratedFunctionArtifact {
    /// Canonical identity of the immutable module program that constructed
    /// this artifact.
    owner_program_id: ContentHash,
    /// Diagnostic/source provenance for the owning program.
    owner_specifier: String,
    /// Content-addressed identity of this construction occurrence.
    artifact_id: ContentHash,
    /// Content-addressed provenance recorded at construction (bd-8enww.3.4).
    provenance: GeneratedFunctionProvenance,
    /// IFC confidentiality label of the source arguments used to construct
    /// this dynamic function artifact (`[RC-C1]` / `g2vrp.8`).
    source_label: Label,
    compiled_module: Arc<Ir3Module>,
    function_index: u32,
}

/// Occurrence identity for a retained generated-function program.
///
/// The owner program alone is insufficient: constructing the same source
/// twice produces distinct realm-owned artifacts whose nested closures must
/// not silently switch occurrence when one of them is later resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GeneratedFunctionArtifactHandle {
    owner_program_id: ContentHash,
    artifact_id: ContentHash,
}

/// Resolve the observable new.target prototype in the caller's module before
/// entering the generated artifact's isolated program and capability envelope.
struct GeneratedFunctionConstruction {
    new_target: Value,
    new_target_label: Label,
    prototype: ObjectId,
}

/// What a grant swap replaced, for its restore (bd-9vouw.189).
struct ReplacedCodegenGrant {
    previous: BTreeSet<RuntimeCapability>,
    /// The swap entered generated code and pushed the caller's grant.
    entered_generated_code: bool,
}

/// Fixed-size representation of the only authority set that generated code
/// may retain across a closure or continuation boundary.
///
/// Keeping the validated capabilities inline is deliberate: suspended
/// generators and async functions must never retain a clone of the caller's
/// potentially dangerous grant set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ContainedCodegenGrant {
    capabilities: [RuntimeCapability; 5],
    len: u8,
}

impl ContainedCodegenGrant {
    fn as_slice(&self) -> &[RuntimeCapability] {
        &self.capabilities[..usize::from(self.len)]
    }
}

// ---------------------------------------------------------------------------
// GeneratorObject — suspended generator state
// ---------------------------------------------------------------------------

/// State of a generator object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum GeneratorPhase {
    /// Created but not yet started (initial .next() call).
    SuspendedStart,
    /// Suspended at a yield point.
    SuspendedYield,
    /// Currently executing.
    Executing,
    /// Completed (returned or threw).
    Completed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GeneratorResumeKind {
    Next,
    Return,
    Throw,
}

/// One suspended `yield*` expression. The canonical iterator table owns the
/// receiver and cached next method; the resume register owns the sent value.
/// Keeping only their handle here avoids a second, unrooted value carrier.
#[derive(Debug, Clone)]
struct GeneratorDelegation {
    iterator: u32,
    label: Label,
    resume_kind: GeneratorResumeKind,
    started: bool,
}

enum GeneratorDelegationStep {
    Yield(LabeledReturn),
    Complete(LabeledReturn),
    Return(LabeledReturn),
}

/// A generator object holds the suspended state of a generator function.
#[derive(Debug, Clone)]
struct GeneratorObject {
    /// Immutable program that owns `function_index` and every suspended
    /// continuation created from it. An imported generator must never
    /// reinterpret this module-local index against the resumer's table.
    owner_module: Arc<Ir3Module>,
    /// Invocation state retained until the first `.next()` enters the frame.
    invocation: Option<GeneratorInvocation>,
    /// Complete execution-local state retained after a `yield`.
    execution: Option<GeneratorExecutionSnapshot>,
    /// Destination register written by the next `.next(value)` resumption.
    resume_dst: Option<u32>,
    /// Current phase of the generator.
    phase: GeneratorPhase,
    /// The object its generator function's `prototype` held at the call
    /// (bd-9vouw.120); `None` when that was no object, so the generator
    /// inherits from %GeneratorPrototype% / %AsyncGeneratorPrototype%.
    prototype: Option<ObjectId>,
}

/// Generator arguments and receiver state captured synchronously at call time.
///
/// The raw trailing arguments deliberately remain unmaterialized until the
/// first frame entry. This matches the engine's existing first-`.next()`
/// parameter timing while ensuring rest arrays are built from the original
/// invocation rather than whichever caller frame happens to be active later.
#[derive(Debug, Clone)]
struct GeneratorInvocation {
    /// Function index in the function table.
    function_index: u32,
    /// Closure index (captures from the enclosing scope).
    closure_index: Option<u32>,
    /// All invocation arguments, including the trailing rest tail.
    arguments: Vec<Value>,
    /// IFC labels parallel to `arguments`.
    argument_labels: Vec<Label>,
    /// Receiver captured for method calls (`undefined` for plain calls).
    this_value: Value,
    /// IFC label paired with `this_value`.
    this_label: Label,
    /// PC-style label active at generator creation.
    inline_context_label: Option<Label>,
    /// Ordinary owner specifier used for relative module resolution.
    module_specifier: Option<String>,
    /// Generated artifact whose program owns `function_index`, when present.
    generated_function_artifact: Option<GeneratedFunctionArtifactHandle>,
}

/// An arguments object's `callee` (ES2020 9.4.4.6-7, bd-9vouw.272).
enum ArgumentsCallee {
    /// A sloppy function with a simple parameter list: a data property
    /// holding the function.
    Function(Value),
    /// Every other function: the %ThrowTypeError% accessor.
    ThrowTypeError,
    /// No `callee` (an arguments object made without call setup, a sloppy
    /// generator's).
    Omitted,
}

/// Complete execution-local activation owned by a suspended generator.
///
/// Heap/closure/realm state remains shared, but every frame-local carrier is
/// transferred as one unit. In particular, values and labels cannot diverge,
/// and an in-flight return/throw/finally completion cannot leak into or inherit
/// state from the caller that resumes the generator.
#[derive(Debug, Clone)]
struct GeneratorExecutionSnapshot {
    /// The register file without its cleared tail (bd-9vouw.167); see
    /// [`GeneratorExecutionSnapshot::trim_cleared_register_tail`].
    registers: Vec<Value>,
    register_labels: Vec<Label>,
    /// The register file's length when the activation was parked, which
    /// `install_generator_execution` restores.
    register_len: usize,
    /// The label file's length then; the two files need not be equally long
    /// (an isolated wrapper replaces the value file and keeps the labels).
    register_label_len: usize,
    /// [`InterpreterCore::register_dirty_end`] of these files, which
    /// `install_generator_execution` restores: the whole file's length would
    /// make the next call after every generator step clear to its end
    /// (bd-9vouw.499).
    register_dirty_end: usize,
    /// [`InterpreterCore::registers_memory_bytes`] of the files when they
    /// were parked, if the core had it cached, which
    /// `install_generator_execution` restores: the trimmed tail and the
    /// padding that replaces it are cleared slots, which own no bytes
    /// (bd-9vouw.500). `None` makes the next read sum the file.
    registers_value_bytes: Option<u64>,
    /// The same for [`InterpreterCore::register_labels_memory_bytes`].
    register_labels_bytes: Option<u64>,
    delegation: Option<GeneratorDelegation>,
    active_inline_callback_context_label: Option<Label>,
    pc_label_stack: Vec<PcLabelFrame>,
    call_stack: Vec<CallFrame>,
    ip: usize,
    register_base: usize,
    register_width: usize,
    catch_frames: Vec<CatchFrame>,
    pending_exception: Option<Value>,
    pending_exception_label: Label,
    pending_hostcall_result_label: Option<Label>,
    pending_return: Option<LabeledReturn>,
    suspended_abrupt_completions: Vec<AbruptCompletion>,
    finally_frames: Vec<FinallyFrame>,
    pending_finally_entry: Option<PendingFinallyEntry>,
    scope_chain: ScopeChain,
    pending_captures: Vec<u32>,
    current_module_specifier: Option<String>,
    active_generated_function_artifact: Option<GeneratedFunctionArtifactHandle>,
    /// Validated contained-codegen authority to reinstall whenever this
    /// generated activation resumes. `None` for ordinary continuations.
    contained_codegen_grant: Option<ContainedCodegenGrant>,
}

impl GeneratorExecutionSnapshot {
    /// Drop the register file's cleared tail, every register past the last
    /// one that is not undefined with a Public label (the state a frame
    /// entry's reset leaves), before the activation is parked. A pending
    /// async call held two full register windows (512 registers on the
    /// deterministic lane, 8,192 on the throughput lane) that were almost all
    /// cleared (bd-9vouw.167). `register_len` keeps the length to restore.
    fn trim_cleared_register_tail(&mut self) {
        let live = live_register_prefix_len(
            &self.registers,
            &self.register_labels,
            self.register_dirty_end,
        );
        if live < self.registers.len() {
            self.registers.truncate(live);
            self.registers.shrink_to_fit();
        }
        if live < self.register_labels.len() {
            self.register_labels.truncate(live);
            self.register_labels.shrink_to_fit();
        }
    }
}

/// Length of the files' live prefix: every register past it is undefined
/// with a Public label, as are the slots one file has past the other's end
/// (bd-9vouw.167). Writes maintain `dirty_end` for both files, so parking an
/// activation need not scan its cleared physical tail on every yield or
/// isolated await (bd-9vouw.500). Clamp each file independently: isolated
/// wrappers can keep a longer label file, and restored bounds can exceed a
/// file that has since been truncated.
fn live_register_prefix_len(
    registers: &[Value],
    register_labels: &[Label],
    dirty_end: usize,
) -> usize {
    let live = live_register_prefix_len_by_walk(
        &registers[..dirty_end.min(registers.len())],
        &register_labels[..dirty_end.min(register_labels.len())],
    );
    debug_assert_eq!(
        live,
        live_register_prefix_len_by_walk(registers, register_labels),
        "a register past register_dirty_end holds a value or non-Public label (bd-9vouw.500)"
    );
    live
}

/// Full-file oracle for the dirty bound, also used on its bounded prefixes.
fn live_register_prefix_len_by_walk(registers: &[Value], register_labels: &[Label]) -> usize {
    let values_end = registers
        .iter()
        .rposition(|value| !matches!(value, Value::Undefined))
        .map_or(0, |index| index + 1);
    let labels_end = register_labels
        .iter()
        .rposition(|label| !matches!(label, Label::Public))
        .map_or(0, |index| index + 1);
    values_end.max(labels_end)
}

/// Make a file whose every slot is `cleared` hold `prefix` followed by
/// cleared slots, `len` in all (at least the prefix).
fn refill_cleared_file<T: Clone>(file: &mut Vec<T>, prefix: Vec<T>, len: usize, cleared: T) {
    file.resize(len.max(prefix.len()), cleared);
    for (slot, value) in file.iter_mut().zip(prefix) {
        *slot = value;
    }
}

/// Execution phases for async function objects.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AsyncFunctionPhase {
    /// Created but not yet started.
    SuspendedStart,
    /// Suspended at an await point.
    SuspendedAwait,
    /// Currently executing.
    Executing,
    /// Completed (resolved or rejected).
    Completed,
}

/// An async function object holds the suspended state of an async function
/// and its result Promise.
#[allow(dead_code)]
#[derive(Debug, Clone)]
struct AsyncFunctionObject {
    /// Immutable program that owns `function_index` and every post-`await`
    /// continuation created from it.
    owner_module: Arc<Ir3Module>,
    /// Complete isolated activation retained when a cross-module async call
    /// suspends inside the owner-module wrapper. Same-module async calls keep
    /// using the already-active execution state and therefore leave this empty.
    isolated_execution: Option<GeneratorExecutionSnapshot>,
    /// Function index in the function table.
    function_index: u32,
    /// Closure index (captures from the enclosing scope).
    closure_index: Option<u32>,
    /// Saved instruction pointer (resume point after await).
    saved_ip: usize,
    /// Saved register file snapshot at the time of await.
    saved_registers: Vec<Value>,
    /// Saved IFC label snapshot parallel to `saved_registers`.
    saved_register_labels: Vec<Label>,
    /// Saved register base offset.
    saved_register_base: usize,
    /// Current phase of the async function.
    phase: AsyncFunctionPhase,
    /// Promise that will be resolved/rejected when the async function completes.
    result_promise: u32,
}

/// Context information for resuming an async function after await.
#[derive(Debug, Clone)]
struct AsyncResumptionContext {
    /// The async function to resume.
    async_function_id: u32,
    /// Register to store the resolved/rejected value.
    result_register: u32,
}

/// The operation to perform when a module-evaluation Promise reaction fires.
#[derive(Debug, Clone)]
enum ModuleAwaitContinuation {
    /// Resume after a source-level `await`, writing the fulfilled value.
    AwaitValue { result_register: u32 },
    /// Resume an importer after an async dependency settles. A rejection is a
    /// module-graph evaluation failure, not a catchable body-level throw.
    Dependency { specifier: String },
}

/// Context for resuming any module after a pending top-level await or async
/// dependency. Imported modules carry their activation in the owning module
/// record; the entry module remains installed in the core.
#[derive(Debug, Clone)]
struct TopLevelAwaitResumptionContext {
    module_specifier: String,
    continuation: ModuleAwaitContinuation,
}

// ---------------------------------------------------------------------------
// CallFrame — interpreter call stack frame
// ---------------------------------------------------------------------------

/// A catch frame pushed by `BeginTry`, popped by `EndTry` or consumed by `Throw`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CatchFrame {
    /// Instruction index of the catch handler.
    catch_target: usize,
    /// Instruction index of the finally block (if present).
    finally_target: Option<usize>,
    /// Call stack depth when the try block was entered.  Used to validate
    /// that the catch frame is still in scope during unwinding.
    call_depth: usize,
    /// Active finally-frame depth when this handler was installed. Abrupt
    /// transfer to this handler exits and discards every owned finalizer
    /// completion above this depth.
    finally_frame_depth: usize,
}

/// Classifies the completion captured when a finally block is entered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum FinallyMode {
    /// Entered via normal control flow (try body completed, or catch body completed).
    Normal,
    /// Entered because an exception was in flight. `EnterFinally` moves it
    /// from the pending slots into the new `FinallyFrame`.
    Exception,
    /// Entered because a return was in flight. `EnterFinally` moves it into
    /// the new `FinallyFrame`.
    Return,
}

/// One-shot ownership record for the exact `EnterFinally` instruction chosen
/// by an unwind edge. It survives an instruction-boundary cancellation,
/// budget refusal, or module snapshot before the target instruction executes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingFinallyEntry {
    target: usize,
    mode: FinallyMode,
}

/// Completion record owned by one actively executing finally body. Keeping
/// the completion in the frame prevents a nested abrupt completion from being
/// suspended and later resurrected after it has been overridden.
#[derive(Debug, Clone)]
struct FinallyFrame {
    completion: Option<AbruptCompletion>,
}

/// A suspended abrupt completion that should resume if a newer one is later
/// consumed locally.
#[derive(Debug, Clone)]
enum AbruptCompletion {
    /// A thrown value plus its IFC label (bd-l0d6z): the label must survive
    /// suspension so a later catch binding inherits the thrown value's taint.
    Exception(Value, Label),
    Return(LabeledReturn),
}

/// Return completion carried while control unwinds through `finally`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LabeledReturn {
    value: Value,
    label: Label,
}

/// Execution boundaries that must leave the large bytecode-dispatch frame
/// before entering a re-entrant runtime operation. This is private control
/// flow, not a guest value or a serialized IR completion.
enum DispatchOutcome {
    Complete(LabeledReturn),
    BuiltinCall {
        builtin: BuiltinFunction,
        callee: u32,
        args: RegRange,
        dst: u32,
        receiver: Option<(Value, u32)>,
    },
    GeneratorDelegate {
        source: u32,
        resume_dst: u32,
    },
    ReentrantInstruction {
        instruction_ip: usize,
        profile_start: Option<std::time::Instant>,
    },
}

/// One fully accounted argument carrier owned by `ApplyHostCall` while it
/// transfers an array-like guest value into the interpreter's scratch
/// register window. The charge is converted into live-register plus saved
/// frame accounting before the delegated dispatch begins.
struct DelegatedHostcallArguments {
    values: Vec<Value>,
    labels: Vec<Label>,
    carrier_bytes: u64,
}

/// Failure-atomic scratch frame for one delegated hostcall (bd-z1peg.3).
///
/// Holds the exact values AND per-element labels displaced from registers
/// `register_base..register_base+count` while a delegated dispatch runs
/// there, together with the byte figures needed to release the frame's
/// physical charge exactly once at restore. `stale_entry_publication` is a
/// pending result label that predated the delegation — quarantined here so
/// it can neither masquerade as the inner dispatch's result nor survive an
/// error.
struct DelegatedHostcallScratchFrame {
    register_base: usize,
    /// `register_width` before the scratch widened it to cover the staged
    /// arguments (bd-9vouw.72).
    saved_register_width: usize,
    required_len: usize,
    original_register_len: usize,
    original_label_len: usize,
    saved_values: Vec<Value>,
    saved_labels: Vec<Label>,
    previous_register_bytes: u64,
    saved_carrier_bytes: u64,
    stale_entry_publication: Option<Label>,
}

// ---------------------------------------------------------------------------
// Scope chain — closure environment support (bd-6a61n.1.1)
// ---------------------------------------------------------------------------

/// Binding kind for `DeclareBinding`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BindingKind {
    Var = 0,
    Let = 1,
    Const = 2,
    Param = 3,
    Function = 4,
    /// A module's import binding (bd-1lsy.4.10.1): immutable, initialized
    /// when its import runs and then kept equal to the exported binding.
    Import = 5,
}

impl BindingKind {
    fn from_u8(val: u8) -> Result<Self, InterpreterError> {
        match val {
            0 => Ok(Self::Var),
            1 => Ok(Self::Let),
            2 => Ok(Self::Const),
            3 => Ok(Self::Param),
            4 => Ok(Self::Function),
            5 => Ok(Self::Import),
            _ => Err(InterpreterError::TypeError {
                expected: "binding kind 0..=5".to_string(),
                got: format!("kind {val}"),
            }),
        }
    }

    fn is_hoisted(self) -> bool {
        matches!(self, Self::Var | Self::Param | Self::Function)
    }

    /// Assigning it is a TypeError: a `const`, or an import (ES2020
    /// 15.2.1.16.4: an import binding is immutable).
    fn is_immutable(self) -> bool {
        matches!(self, Self::Const | Self::Import)
    }
}

/// Mutable state shared by every scope/closure view of one lexical binding.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ScopeBindingState {
    value: Value,
    /// IFC label owned by the lexical cell alongside its value.
    ///
    /// Keeping the label in the shared cell is essential: closure snapshots
    /// clone the `Rc` handle, and per-iteration environments deliberately
    /// replace that handle with a detached cell. A parallel register-only
    /// label would therefore be lost on every scoped store/load round trip.
    label: Label,
    /// `true` once initialized (let/const start uninitialized in TDZ).
    initialized: bool,
    /// 1 + the index in `ModuleState::live_exports` of the exports this
    /// module binding backs (bd-1lsy.4.10.1); a write republishes them.
    live_export: Option<std::num::NonZeroU32>,
}

/// A single binding in a scope environment.
///
/// Cloning a scope frame must preserve lexical binding identity. A fresh
/// declaration creates a fresh cell, while closure/snapshot clones share the
/// existing cell so reads and writes remain live across every view.
#[derive(Debug, Clone)]
struct ScopeBinding {
    kind: BindingKind,
    state: Rc<RefCell<ScopeBindingState>>,
}

/// Exact Reference identity captured before an assignment RHS is evaluated.
///
/// The IR status register carries an opaque table index rather than the cell
/// itself. This keeps [`Value`] JavaScript-facing while allowing generators,
/// async functions, module wrappers, and inline callbacks to preserve the
/// original environment-record target in their ordinary saved registers.
#[derive(Debug, Clone)]
enum RuntimeNameReference {
    Unresolvable,
    RealmGlobal,
    Resolved(ScopeBinding),
}

impl RuntimeNameReference {
    fn same_identity(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Unresolvable, Self::Unresolvable) => true,
            (Self::RealmGlobal, Self::RealmGlobal) => true,
            (Self::Resolved(left), Self::Resolved(right)) => {
                left.kind == right.kind && Rc::ptr_eq(&left.state, &right.state)
            }
            _ => false,
        }
    }
}

impl ScopeBinding {
    fn new(kind: BindingKind) -> Self {
        Self::with_state(kind, Value::Undefined, kind.is_hoisted())
    }

    fn with_state(kind: BindingKind, value: Value, initialized: bool) -> Self {
        Self::with_labeled_state(kind, value, Label::Public, initialized)
    }

    fn with_labeled_state(
        kind: BindingKind,
        value: Value,
        label: Label,
        initialized: bool,
    ) -> Self {
        Self {
            kind,
            state: Rc::new(RefCell::new(ScopeBindingState {
                value,
                label,
                initialized,
                live_export: None,
            })),
        }
    }

    fn state(&self) -> Result<Ref<'_, ScopeBindingState>, InterpreterError> {
        self.state
            .try_borrow()
            .map_err(|_| InterpreterError::InternalError {
                details: "scope binding state is already mutably borrowed".to_string(),
            })
    }

    fn state_mut(&self) -> Result<RefMut<'_, ScopeBindingState>, InterpreterError> {
        self.state
            .try_borrow_mut()
            .map_err(|_| InterpreterError::InternalError {
                details: "scope binding state is already borrowed".to_string(),
            })
    }

    fn snapshot_state(&self) -> Result<ScopeBindingState, InterpreterError> {
        Ok(self.state()?.clone())
    }

    fn detached_clone(&self) -> Result<Self, InterpreterError> {
        let state = self.snapshot_state()?;
        Ok(Self::with_labeled_state(
            self.kind,
            state.value,
            state.label,
            state.initialized,
        ))
    }

    fn restore_state(&self, previous: ScopeBindingState) -> Result<(), InterpreterError> {
        *self.state_mut()? = previous;
        Ok(())
    }

    #[cfg(test)]
    fn set_state(&self, value: Value, initialized: bool) -> Result<(), InterpreterError> {
        let mut state = self.state_mut()?;
        state.value = value;
        state.initialized = initialized;
        Ok(())
    }

    #[cfg(test)]
    fn value(&self) -> Result<Value, InterpreterError> {
        Ok(self.state()?.value.clone())
    }

    #[cfg(test)]
    fn label(&self) -> Result<Label, InterpreterError> {
        Ok(self.state()?.label.clone())
    }
}

/// A single scope frame in the environment chain.
///
/// The binding map is shared copy-on-write. Closure captures and saved caller
/// chains clone the `Rc`. The first structural change to a shared frame copies
/// the map, so every view keeps exactly what a deep clone gave it. Values live
/// in the shared `ScopeBinding` cells either way. Before this, every closure
/// call deep-copied every captured binding name, twice.
#[derive(Debug, Clone)]
struct ScopeFrame {
    bindings: Rc<FrameBindings>,
    /// Sum of [`Self::binding_key_bytes`] over `bindings`, kept current by
    /// every structural change so a scope-chain clone charge is O(depth).
    key_bytes: u64,
}

/// A scope frame's binding map, shared copy-on-write by the frames that alias
/// it, plus how many registrations in the cold-cell ledger hold it
/// (bd-9vouw.154). The ledger charges a held map's key bytes once; the count
/// lives with the map so the live-chain accounting can tell in O(1) which
/// maps it still charges itself. A copy-on-write copy is a new map that no
/// registration holds.
#[derive(Debug, Default)]
struct FrameBindings {
    map: BTreeMap<String, ScopeBinding>,
    ledger_holds: Cell<usize>,
}

impl Clone for FrameBindings {
    fn clone(&self) -> Self {
        Self {
            map: self.map.clone(),
            ledger_holds: Cell::new(0),
        }
    }
}

impl std::ops::Deref for FrameBindings {
    type Target = BTreeMap<String, ScopeBinding>;

    fn deref(&self) -> &Self::Target {
        &self.map
    }
}

impl ScopeFrame {
    fn new() -> Self {
        Self {
            bindings: Rc::new(FrameBindings::default()),
            key_bytes: 0,
        }
    }

    fn from_bindings(bindings: BTreeMap<String, ScopeBinding>) -> Self {
        let key_bytes = InterpreterCore::saturating_sum(
            bindings.keys().map(|name| Self::binding_key_bytes(name)),
        );
        Self {
            bindings: Rc::new(FrameBindings {
                map: bindings,
                ledger_holds: Cell::new(0),
            }),
            key_bytes,
        }
    }

    /// Structural bytes of one binding entry: its base plus its name.
    fn binding_key_bytes(name: &str) -> u64 {
        MEMORY_ESTIMATE_SCOPE_BINDING_BASE_BYTES
            .saturating_add(InterpreterCore::estimate_string_bytes(name))
    }

    fn declare<'name>(
        &mut self,
        name: impl Into<Cow<'name, str>>,
        kind: BindingKind,
    ) -> Option<ScopeBinding> {
        let name = name.into();
        if kind == BindingKind::Var
            && let Some(existing) = self.bindings.get(name.as_ref())
        {
            return Some(existing.clone());
        }
        // Bytecode names normally borrow the immutable constant pool. Own the
        // key only when a declaration actually changes the frame; a repeated
        // `var` keeps its existing key, cell, and shared map without copying.
        self.insert_binding(name.into_owned(), ScopeBinding::new(kind))
    }

    fn insert_binding(&mut self, name: String, binding: ScopeBinding) -> Option<ScopeBinding> {
        let added = Self::binding_key_bytes(&name);
        let replaced = Rc::make_mut(&mut self.bindings).map.insert(name, binding);
        if replaced.is_none() {
            self.key_bytes = self.key_bytes.saturating_add(added);
        }
        replaced
    }

    /// The frame's map before a change that may be refused, when other
    /// holders share it (so the change will copy it on write anyway). `None`
    /// when this frame alone owns the map: the change is made in place and
    /// holding a second handle here would force a copy.
    fn bindings_checkpoint(&self) -> Option<(Rc<FrameBindings>, u64)> {
        (Rc::strong_count(&self.bindings) > 1).then(|| (Rc::clone(&self.bindings), self.key_bytes))
    }

    /// Undo a refused change that copied a shared map on write: put the
    /// original map back, still shared. Removing the change from the copy
    /// would leave two maps where the estimate charged one (bd-9vouw.154).
    /// `false` when the change was made in place, for the caller to undo.
    fn restore_copied_bindings(&mut self, checkpoint: Option<(Rc<FrameBindings>, u64)>) -> bool {
        match checkpoint {
            Some((original, key_bytes)) if !Rc::ptr_eq(&original, &self.bindings) => {
                self.bindings = original;
                self.key_bytes = key_bytes;
                true
            }
            _ => false,
        }
    }

    fn remove_binding(&mut self, name: &str) -> Option<ScopeBinding> {
        if !self.bindings.contains_key(name) {
            return None;
        }
        let removed = Rc::make_mut(&mut self.bindings).map.remove(name);
        if removed.is_some() {
            self.key_bytes = self.key_bytes.saturating_sub(Self::binding_key_bytes(name));
        }
        removed
    }

    fn replace_bindings(&mut self, bindings: BTreeMap<String, ScopeBinding>) {
        *self = Self::from_bindings(bindings);
    }

    fn get(&self, name: &str) -> Option<&ScopeBinding> {
        self.bindings.get(name)
    }

    fn get_mut(&mut self, name: &str) -> Option<&mut ScopeBinding> {
        if !self.bindings.contains_key(name) {
            return None;
        }
        Rc::make_mut(&mut self.bindings).map.get_mut(name)
    }
}

/// A scope chain is a stack of scope frames. Innermost is last.
#[derive(Debug, Clone)]
struct ScopeChain {
    frames: Vec<ScopeFrame>,
}

impl ScopeChain {
    fn new() -> Self {
        // Start with a global scope.
        Self {
            frames: vec![ScopeFrame::new()],
        }
    }

    fn push(&mut self, max_scope_depth: u32) -> Result<(), InterpreterError> {
        Self::preflight_push_depth(self.frames.len(), max_scope_depth)?;
        self.frames.push(ScopeFrame::new());
        Ok(())
    }

    fn preflight_push_depth(
        current_depth: usize,
        max_scope_depth: u32,
    ) -> Result<(), InterpreterError> {
        let max_scope_depth = usize::try_from(max_scope_depth).unwrap_or(usize::MAX);
        if current_depth >= max_scope_depth {
            return Err(InterpreterError::ScopeDepthExceeded {
                requested_depth: current_depth.saturating_add(1),
                max_depth: max_scope_depth,
            });
        }
        Ok(())
    }

    fn pop(&mut self) -> Option<ScopeFrame> {
        if self.frames.len() > 1 {
            return self.frames.pop();
        }
        None
    }

    fn current(&self) -> Result<&ScopeFrame, InterpreterError> {
        self.frames
            .last()
            .ok_or_else(|| InterpreterError::InternalError {
                details: "scope chain unexpectedly empty".to_string(),
            })
    }

    fn current_mut(&mut self) -> Result<&mut ScopeFrame, InterpreterError> {
        // Scope chain is initialized with global frame and should never be emptied
        self.frames
            .last_mut()
            .ok_or_else(|| InterpreterError::InternalError {
                details: "scope chain unexpectedly empty".to_string(),
            })
    }

    /// Resolve a binding by walking outward from innermost scope.
    fn resolve(&self, name: &str) -> Option<(usize, &ScopeBinding)> {
        for (idx, frame) in self.frames.iter().enumerate().rev() {
            if let Some(binding) = frame.get(name) {
                return Some((idx, binding));
            }
        }
        None
    }

    /// Whether any frame binds `name`: `resolve(name).is_some()`, scanning
    /// from the outermost frame, where a module's CommonJS bindings live
    /// (bd-9vouw.504: the innermost-first walk cost every PushScope of
    /// CommonJS code about 18 key comparisons).
    fn binds(&self, name: &str) -> bool {
        self.frames.iter().any(|frame| frame.get(name).is_some())
    }

    /// Snapshot current scope chain for closure capture.
    fn snapshot(&self) -> Vec<ScopeFrame> {
        self.frames.clone()
    }

    /// Depth of the scope chain.
    fn depth(&self) -> usize {
        self.frames.len()
    }
}

/// A closure value: function code reference + captured environment.
#[derive(Debug, Clone)]
struct ClosureValue {
    function_index: u32,
    /// Captured scope chain snapshot at closure creation time.
    captured_env: Vec<ScopeFrame>,
}

/// One binding cell held by a long-lived accounting surface (bd-9vouw.31).
#[derive(Debug, Clone)]
struct ColdBindingCell {
    /// Keeps the allocation alive so the address key cannot be reused by a
    /// different cell while this entry exists.
    _cell: Weak<RefCell<ScopeBindingState>>,
    /// Number of binding entries across the cold surfaces that alias the cell.
    aliases: usize,
    /// Payload charged for the cell, refreshed on every write to it.
    charged_bytes: u64,
}

/// Exact ledger of the binding cells reachable from closure captured
/// environments and suspended generator / isolated async activations
/// (bd-9vouw.31).
///
/// bd-sblaq charges each physical cell's payload exactly once across every
/// accounted surface. Deriving that by walking every closure environment on
/// each scope operation made every operation O(live closures), so programs
/// with N live closures or pending async calls ran in O(N^2). These surfaces
/// change only when a closure is created or rolled back, when an activation is
/// parked or resumed, and when one of their cells is written, so the deduped
/// payload is maintained at those points. [`CallStack`] registers the saved
/// caller chains of the frames below the top one here too (bd-9vouw.72). The
/// live scope chain and the top frame's saved chain are still walked per
/// operation, skipping cells this ledger already charges;
/// `shared_binding_cell_payloads_memory_bytes` remains the full-walk oracle.
///
/// The ledger also charges the key bytes of each registered map once
/// (bd-9vouw.154): closures, suspended activations and saved caller chains
/// share their frame maps, so charging every holder for the whole map made N
/// closures (or N pending async calls, or a recursion N deep) over a scope of
/// B bindings cost O(N x B) of the budget while the process held O(N + B).
/// The holders charge only their own frame slots.
///
/// Not `Clone`: the holder counts live in the shared maps, so a copy of the
/// ledger would disagree with them.
#[derive(Debug, Default)]
struct ColdBindingCells {
    cells: BTreeMap<usize, ColdBindingCell>,
    payload_bytes: u64,
    /// Registered bindings maps, by address: the map itself and the key
    /// bytes charged for it. How many registrations hold a map is its
    /// `ledger_holds`. A map's cells are registered by its first
    /// registration and released by its last, so re-registering a scope that
    /// is already held (the global scope, at every call) costs O(1), not
    /// O(bindings), and does not search this map. Holding the `Rc` makes
    /// every structural write elsewhere copy the map first
    /// (`Rc::make_mut`), so a registered map's bindings cannot change while
    /// it is held.
    maps: BTreeMap<usize, (Rc<FrameBindings>, u64)>,
    /// Key bytes of the registered maps, each map once.
    map_key_bytes: u64,
}

impl ColdBindingCells {
    fn key(cell: &Rc<RefCell<ScopeBindingState>>) -> usize {
        Rc::as_ptr(cell) as usize
    }

    fn contains(&self, cell: &Rc<RefCell<ScopeBindingState>>) -> bool {
        self.cells.contains_key(&Self::key(cell))
    }

    fn register_cell(&mut self, cell: &Rc<RefCell<ScopeBindingState>>) {
        match self.cells.entry(Self::key(cell)) {
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                entry.get_mut().aliases += 1;
            }
            std::collections::btree_map::Entry::Vacant(entry) => {
                let charged_bytes = InterpreterCore::estimate_binding_cell_payload_bytes(cell);
                self.payload_bytes = self.payload_bytes.saturating_add(charged_bytes);
                entry.insert(ColdBindingCell {
                    _cell: Rc::downgrade(cell),
                    aliases: 1,
                    charged_bytes,
                });
            }
        }
    }

    fn release_cell(&mut self, cell: &Rc<RefCell<ScopeBindingState>>) {
        let std::collections::btree_map::Entry::Occupied(mut entry) =
            self.cells.entry(Self::key(cell))
        else {
            debug_assert!(false, "released a binding cell the ledger does not hold");
            return;
        };
        let record = entry.get_mut();
        record.aliases -= 1;
        if record.aliases == 0 {
            self.payload_bytes = self.payload_bytes.saturating_sub(record.charged_bytes);
            entry.remove();
        }
    }

    fn map_key(frame: &ScopeFrame) -> usize {
        Rc::as_ptr(&frame.bindings) as usize
    }

    /// Whether every cell and the key bytes of `frame` are charged here: its
    /// map is held. O(1) through the count kept in the map.
    fn holds_frame(&self, frame: &ScopeFrame) -> bool {
        let held = frame.bindings.ledger_holds.get() > 0;
        debug_assert_eq!(
            held,
            self.maps.contains_key(&Self::map_key(frame)),
            "a frame map's ledger count drifted from the ledger (bd-9vouw.154)"
        );
        held
    }

    fn register_frames(&mut self, frames: &[ScopeFrame]) {
        for frame in frames {
            let holds = &frame.bindings.ledger_holds;
            let previous = holds.get();
            holds.set(previous + 1);
            if previous > 0 {
                continue;
            }
            let replaced = self.maps.insert(
                Self::map_key(frame),
                (Rc::clone(&frame.bindings), frame.key_bytes),
            );
            debug_assert!(
                replaced.is_none(),
                "an unheld scope map was in the ledger (bd-9vouw.154)"
            );
            self.map_key_bytes = self.map_key_bytes.saturating_add(frame.key_bytes);
            for binding in frame.bindings.values() {
                self.register_cell(&binding.state);
            }
        }
    }

    fn release_frames(&mut self, frames: &[ScopeFrame]) {
        for frame in frames {
            let holds = &frame.bindings.ledger_holds;
            let previous = holds.get();
            if previous == 0 {
                debug_assert!(false, "released a scope map the ledger does not hold");
                continue;
            }
            holds.set(previous - 1);
            if previous > 1 {
                continue;
            }
            let Some((bindings, key_bytes)) = self.maps.remove(&Self::map_key(frame)) else {
                debug_assert!(
                    false,
                    "a held scope map was not in the ledger (bd-9vouw.154)"
                );
                continue;
            };
            self.map_key_bytes = self.map_key_bytes.saturating_sub(key_bytes);
            for binding in bindings.values() {
                self.release_cell(&binding.state);
            }
        }
    }

    /// Frames reachable from a suspended activation: its scope chain and
    /// every call frame's saved caller chain (the surfaces
    /// `accumulate_generator_execution_cell_payload_bytes` walks).
    fn register_activation(&mut self, execution: &GeneratorExecutionSnapshot) {
        self.register_frames(&execution.scope_chain.frames);
        for frame in &execution.call_stack {
            if let Some(saved) = &frame.saved_scope_chain {
                self.register_frames(saved);
            }
        }
    }

    fn release_activation(&mut self, execution: &GeneratorExecutionSnapshot) {
        self.release_frames(&execution.scope_chain.frames);
        for frame in &execution.call_stack {
            if let Some(saved) = &frame.saved_scope_chain {
                self.release_frames(saved);
            }
        }
    }

    /// Re-charge a cell after its value or label was written. A cell no cold
    /// surface holds is charged by the live walk instead.
    fn refresh_cell(&mut self, cell: &Rc<RefCell<ScopeBindingState>>) {
        if let Some(record) = self.cells.get_mut(&Self::key(cell)) {
            let next_bytes = InterpreterCore::estimate_binding_cell_payload_bytes(cell);
            self.payload_bytes = self
                .payload_bytes
                .saturating_sub(record.charged_bytes)
                .saturating_add(next_bytes);
            record.charged_bytes = next_bytes;
        }
    }
}

/// Closure-table entries per chunk. As with heap slots, a full chunk whose
/// closures were all reclaimed is released (bd-9vouw.57).
const CLOSURE_CHUNK_SLOTS: usize = HEAP_CHUNK_SLOTS;

#[derive(Debug, Clone, Default)]
struct ClosureChunk {
    entries: Vec<ClosureValue>,
    /// Entries not yet reclaimed.
    live: usize,
}

/// The closure store plus the running accounting totals derived from it
/// (bd-9vouw.31). Entries are only appended, popped on rollback, cleared, or
/// reclaimed by the collector, so each closure's own structure is summed as
/// closures come and go, and each captured frame map (its key bytes and
/// cells) is registered in the shared cold-cell ledger. Reads go through
/// `get`, `len` and `iter`; there is deliberately no mutable access to an
/// entry.
///
/// Closure ids are never reused. A reclaimed closure reads as an entry with
/// `RECLAIMED_CLOSURE_FUNCTION_INDEX`, so calling it fails; once every
/// closure of a full chunk is reclaimed, the chunk itself is released.
#[derive(Debug)]
struct ClosureTable {
    /// `None`: a released chunk, every entry of which was reclaimed.
    chunks: Vec<Option<ClosureChunk>>,
    len: usize,
    /// What an entry of a released chunk reads as.
    reclaimed: ClosureValue,
    /// Sum of `InterpreterCore::estimate_closure_alias_bytes` over the
    /// entries.
    structural_bytes: u64,
    /// Cells reachable from closure environments and from suspended
    /// generator / isolated async activations, deduplicated across both.
    cold_cells: ColdBindingCells,
}

impl Default for ClosureTable {
    fn default() -> Self {
        Self {
            chunks: Vec::new(),
            len: 0,
            reclaimed: ClosureValue {
                function_index: RECLAIMED_CLOSURE_FUNCTION_INDEX,
                captured_env: Vec::new(),
            },
            structural_bytes: 0,
            cold_cells: ColdBindingCells::default(),
        }
    }
}

impl ClosureTable {
    fn len(&self) -> usize {
        self.len
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn get(&self, index: usize) -> Option<&ClosureValue> {
        if index >= self.len {
            return None;
        }
        match &self.chunks[index / CLOSURE_CHUNK_SLOTS] {
            Some(chunk) => chunk.entries.get(index % CLOSURE_CHUNK_SLOTS),
            None => Some(&self.reclaimed),
        }
    }

    /// Entries of resident chunks. Released chunks hold only reclaimed
    /// closures, which have no captured environment and are charged nothing.
    fn iter(&self) -> impl Iterator<Item = &ClosureValue> {
        self.chunks
            .iter()
            .flatten()
            .flat_map(|chunk| chunk.entries.iter())
    }

    /// Ids of closures that have not been reclaimed.
    fn live_indices(&self) -> impl Iterator<Item = usize> + '_ {
        self.chunks
            .iter()
            .enumerate()
            .filter_map(|(chunk_index, chunk)| chunk.as_ref().map(|chunk| (chunk_index, chunk)))
            .flat_map(|(chunk_index, chunk)| {
                chunk
                    .entries
                    .iter()
                    .enumerate()
                    .filter(|(_, closure)| {
                        closure.function_index != RECLAIMED_CLOSURE_FUNCTION_INDEX
                    })
                    .map(move |(offset, _)| chunk_index * CLOSURE_CHUNK_SLOTS + offset)
            })
    }

    fn push(&mut self, closure: ClosureValue) {
        self.structural_bytes = self
            .structural_bytes
            .saturating_add(InterpreterCore::estimate_closure_alias_bytes(&closure));
        self.cold_cells.register_frames(&closure.captured_env);
        if self.len.is_multiple_of(CLOSURE_CHUNK_SLOTS) {
            self.chunks.push(Some(ClosureChunk::default()));
        }
        // Only a full chunk is ever released, so the tail chunk is resident.
        let chunk = self
            .chunks
            .last_mut()
            .and_then(Option::as_mut)
            .expect("the closure tail chunk is resident");
        if closure.function_index != RECLAIMED_CLOSURE_FUNCTION_INDEX {
            chunk.live += 1;
        }
        chunk.entries.push(closure);
        self.len += 1;
    }

    fn pop(&mut self) -> Option<ClosureValue> {
        let index = self.len.checked_sub(1)?;
        let chunk_index = index / CLOSURE_CHUNK_SLOTS;
        if self.chunks[chunk_index].is_none() {
            // Popping into a released chunk: its remaining entries are dead.
            self.chunks[chunk_index] = Some(ClosureChunk {
                entries: vec![self.reclaimed.clone(); CLOSURE_CHUNK_SLOTS],
                live: 0,
            });
        }
        let chunk = self.chunks[chunk_index]
            .as_mut()
            .expect("chunk was just made resident");
        let closure = chunk.entries.pop()?;
        if closure.function_index != RECLAIMED_CLOSURE_FUNCTION_INDEX {
            chunk.live -= 1;
        }
        self.len = index;
        if self.len.is_multiple_of(CLOSURE_CHUNK_SLOTS) {
            self.chunks.truncate(self.len / CLOSURE_CHUNK_SLOTS);
        }
        self.structural_bytes = self
            .structural_bytes
            .saturating_sub(InterpreterCore::estimate_closure_alias_bytes(&closure));
        self.cold_cells.release_frames(&closure.captured_env);
        Some(closure)
    }

    fn clear(&mut self) {
        while self.pop().is_some() {}
    }

    /// Collector (bd-9vouw.57): release an unreachable closure's captured
    /// environment and poison its function index. The id is never reused;
    /// calling a reclaimed closure fails on the out-of-range function index
    /// instead of running with another closure's environment. A full chunk
    /// left with no live closure is released. Returns whether the closure
    /// was live.
    fn reclaim(&mut self, index: usize) -> bool {
        let chunk_index = index / CLOSURE_CHUNK_SLOTS;
        let Some(Some(chunk)) = self.chunks.get_mut(chunk_index) else {
            return false;
        };
        let Some(closure) = chunk.entries.get_mut(index % CLOSURE_CHUNK_SLOTS) else {
            return false;
        };
        if closure.function_index == RECLAIMED_CLOSURE_FUNCTION_INDEX {
            return false;
        }
        let previous_bytes = InterpreterCore::estimate_closure_alias_bytes(closure);
        let captured_env = std::mem::take(&mut closure.captured_env);
        closure.function_index = RECLAIMED_CLOSURE_FUNCTION_INDEX;
        chunk.live -= 1;
        if chunk.live == 0 && chunk.entries.len() == CLOSURE_CHUNK_SLOTS {
            self.chunks[chunk_index] = None;
        }
        self.structural_bytes = self.structural_bytes.saturating_sub(previous_bytes);
        self.cold_cells.release_frames(&captured_env);
        true
    }

    fn structural_bytes(&self) -> u64 {
        self.structural_bytes
    }

    /// Call after writing a binding cell's value or label, once the write
    /// borrow is released, so a cell held by a cold surface is re-charged.
    fn refresh_cell(&mut self, cell: &Rc<RefCell<ScopeBindingState>>) {
        self.cold_cells.refresh_cell(cell);
    }

    /// Store `next` in a suspended-activation slot, keeping the cold-cell
    /// ledger exact, and return the previous occupant.
    fn replace_activation(
        &mut self,
        slot: &mut Option<GeneratorExecutionSnapshot>,
        next: Option<GeneratorExecutionSnapshot>,
    ) -> Option<GeneratorExecutionSnapshot> {
        if let Some(execution) = &next {
            self.cold_cells.register_activation(execution);
        }
        let previous = std::mem::replace(slot, next);
        if let Some(execution) = &previous {
            self.cold_cells.release_activation(execution);
        }
        previous
    }
}

impl std::ops::Index<usize> for ClosureTable {
    type Output = ClosureValue;

    fn index(&self, index: usize) -> &ClosureValue {
        self.get(index)
            .unwrap_or_else(|| panic!("closure {index} out of bounds ({})", self.len))
    }
}

/// A closure-id keyed side table that keeps the running total of its entries'
/// estimated bytes (bd-9vouw.31), so the closure accounting component does not
/// re-walk every entry on each call setup and closure creation. Reads go
/// through `Deref<Target = BTreeMap>`; writes must use `insert` / `remove`.
#[derive(Debug, Clone)]
struct ClosureSideTable<V> {
    entries: BTreeMap<u32, V>,
    bytes: u64,
    entry_bytes: fn(&V) -> u64,
}

impl<V> ClosureSideTable<V> {
    fn new(entry_bytes: fn(&V) -> u64) -> Self {
        Self {
            entries: BTreeMap::new(),
            bytes: 0,
            entry_bytes,
        }
    }

    fn insert(&mut self, closure_id: u32, value: V) -> Option<V> {
        let added = (self.entry_bytes)(&value);
        let previous = self.entries.insert(closure_id, value);
        let removed = previous.as_ref().map_or(0, self.entry_bytes);
        self.bytes = self.bytes.saturating_sub(removed).saturating_add(added);
        previous
    }

    fn remove(&mut self, closure_id: &u32) -> Option<V> {
        let previous = self.entries.remove(closure_id);
        if let Some(value) = &previous {
            self.bytes = self.bytes.saturating_sub((self.entry_bytes)(value));
        }
        previous
    }

    fn clear(&mut self) {
        self.entries.clear();
        self.bytes = 0;
    }

    fn bytes(&self) -> u64 {
        self.bytes
    }
}

impl<V> std::ops::Deref for ClosureSideTable<V> {
    type Target = BTreeMap<u32, V>;

    fn deref(&self) -> &BTreeMap<u32, V> {
        &self.entries
    }
}

/// Private, per-closure state installed by `DefineMethod`.
///
/// This must not live in guest-visible properties or be keyed by a function
/// table index: one compiled method body can be evaluated repeatedly with a
/// different inferred name and [[HomeObject]] on every closure occurrence.
#[derive(Debug, Clone)]
struct ClosureMethodMetadata {
    home_object: ObjectId,
    name: JsString,
    definition_label: Label,
}

/// Lexically captured `super` binding for a closure created while a concise
/// method frame is active.
///
/// The source parser permits `super` in nested arrows, including arrows that
/// escape the method invocation. Keeping this state beside the closure
/// occurrence (rather than borrowing the invocation-time caller frame) makes
/// that binding survive after the defining method returns. The HomeObject is
/// retained instead of its then-current prototype so later prototype changes
/// remain observable.
#[derive(Debug, Clone)]
struct ClosureLexicalSuperMetadata {
    home_object: ObjectId,
    definition_label: Label,
    this_value: Value,
    this_label: Label,
}

type RestoredAbruptCompletionState = (Option<(Value, Label)>, Option<LabeledReturn>);

/// A call stack frame.
#[derive(Debug, Clone)]
struct CallFrame {
    /// Return address (instruction index to resume at in caller).
    return_ip: usize,
    /// Register where the return value should be placed.
    return_reg: u32,
    /// Base register offset for this frame (reserved for frame isolation).
    register_base: usize,
    /// The caller's register-window width, restored with `register_base`
    /// (bd-9vouw.72).
    register_width: usize,
    /// Function table index (reserved for frame-level diagnostics).
    #[allow(dead_code)]
    function_index: Option<u32>,
    /// The `this` value for this call frame.  Set to the receiver for method
    /// calls, `undefined` for plain calls, or the newly allocated object for
    /// constructor calls.  Arrow functions inherit from the defining frame.
    this_value: Value,
    /// IFC label paired with `this_value` for receiver-aware calls.
    this_label: Label,
    /// The `new.target` value for this call frame. Constructor calls set this
    /// to the invoked constructor value; non-constructor calls use undefined.
    new_target_value: Value,
    /// IFC label paired with `new_target_value`.
    new_target_label: Label,
    /// The `super` value for this call frame. Set to the parent class constructor
    /// for class methods, `undefined` otherwise.
    super_value: Value,
    /// IFC label paired with `super_value`.
    super_label: Label,
    /// Concise methods retain their actual [[HomeObject]] so each `LoadSuper`
    /// observes that object's current internal prototype, including changes
    /// made after method entry. Class-constructor frames use `None` and retain
    /// the explicit `super_value` carrier above.
    super_home_object: Option<ObjectId>,
    /// For constructor calls (`new`): the `this` object allocated before
    /// entering the constructor body. If the constructor returns a non-object,
    /// this value is used as the result instead (ES2020 §9.2.2 step 13).
    construct_this: Option<Value>,
    /// Whether this is a derived constructor activation.
    derived_constructor: bool,
    /// Whether `super()` has initialized this derived activation's `this`.
    this_initialized: bool,
    /// Whether this frame was entered by `super()` and must initialize the
    /// immediately enclosing derived activation when it completes.
    initialize_derived_this_on_return: bool,
    /// A derived class constructor's instance field list (see
    /// [`HeapObject::class_fields`]), run once its `super()` returns.
    class_instance_fields: Option<Value>,
    /// Caller exception state saved across the call so callee control flow
    /// cannot clobber an outer in-flight abrupt completion.
    saved_pending_exception: Option<Value>,
    /// IFC label for `saved_pending_exception` (bd-l0d6z): the thrown value's
    /// label must survive call-boundary save/restore.
    saved_pending_exception_label: Label,
    /// Caller return value and IFC label saved for the same reason.
    saved_pending_return: Option<LabeledReturn>,
    /// Count of suspended abrupt completions before entering the callee.
    saved_suspended_abrupt_depth: usize,
    /// Count of active finally completion frames before entering the callee.
    saved_finally_mode_depth: usize,
    /// Scope chain depth before entering the callee, restored on return.
    saved_scope_depth: usize,
    /// Full scope chain snapshot saved before a closure call replaces
    /// the chain with the captured environment. A verified scope-inert frame
    /// instead retains the captured environment here while leaving the caller
    /// active; terminal-error materialization swaps the two representations.
    /// `None` for plain function calls where the chain is only extended.
    saved_scope_chain: Option<Vec<ScopeFrame>>,
    /// Logical empty-local-scope bytes retained by a verified Tier-I leaf that
    /// cannot inspect or mutate any lexical environment, create a closure, or
    /// re-enter guest code. The captured environment, when present, lives in
    /// `saved_scope_chain`; a non-zero value marks the optimized activation.
    scope_inert_virtual_scope_bytes: u64,
    /// Async function object that owns the result promise for this frame.
    async_function_id: Option<u32>,
    /// A builtin running a guest callback sits below this frame (a nested
    /// same-module callback): exception routing, async rejection and
    /// abrupt-completion clearing never reach past it.
    native_boundary: bool,
}

/// The live call stack (bd-9vouw.72).
///
/// Every call and return used to re-sum all frames' memory estimates and walk
/// every frame's saved caller chain, before and after its setup, so a call at
/// depth d cost O(d) and plain recursion was quadratic. A frame below the top
/// cannot change while a frame above it is live, so the frames below the top
/// are a running total here and their saved caller chains are registered in
/// the cold binding-cell ledger, as a parked activation's are. Only the top
/// frame, which `last_mut` may change, is measured on demand, at most once
/// between changes. Reads deref to a slice; every other mutation goes through
/// these methods.
#[derive(Debug, Default)]
struct CallStack {
    frames: Vec<CallFrame>,
    /// [`InterpreterCore::estimate_live_call_frame_bytes`] summed over every
    /// frame but the top one.
    below_top_bytes: u64,
    /// For each frame below the top, its estimate when a frame was pushed
    /// over it, which `pop` restores as the top's without measuring it again.
    below_top_frame_bytes: Vec<u64>,
    /// The top frame's estimate since it was last measured. A frame's
    /// estimate depends only on its own fields (a string's retained bytes
    /// are fixed when it is built, a saved chain is charged per frame), so
    /// only `push`, `pop`, `take` and `last_mut` clear it. Every call and
    /// return measured the top frame about six times (bd-9vouw.497).
    top_bytes: Cell<Option<u64>>,
    /// For each frame below the top, the index of the first frame at or
    /// below it with the strictly greatest `super_label` among the frames
    /// that carry a HomeObject (`active_execution_context_label`).
    below_top_super_winner: Vec<Option<usize>>,
}

impl std::ops::Deref for CallStack {
    type Target = [CallFrame];

    fn deref(&self) -> &[CallFrame] {
        &self.frames
    }
}

impl CallStack {
    /// Estimated bytes of all frames.
    fn frame_bytes(&self) -> u64 {
        self.below_top_bytes.saturating_add(self.top_frame_bytes())
    }

    /// [`InterpreterCore::estimate_live_call_frame_bytes`] of the top frame.
    fn top_frame_bytes(&self) -> u64 {
        if let Some(bytes) = self.top_bytes.get() {
            return bytes;
        }
        let bytes = self
            .frames
            .last()
            .map_or(0, InterpreterCore::estimate_live_call_frame_bytes);
        self.top_bytes.set(Some(bytes));
        bytes
    }

    /// The top frame's saved caller chain, the only saved chain the live-only
    /// scope walk still visits.
    fn top_saved_scope_chain(&self) -> Option<&[ScopeFrame]> {
        self.frames
            .last()
            .and_then(|frame| frame.saved_scope_chain.as_deref())
    }

    fn push(&mut self, frame: CallFrame, cold: &mut ColdBindingCells) {
        let covered_bytes = self.top_frame_bytes();
        if let Some(top) = self.frames.last() {
            self.below_top_bytes = self.below_top_bytes.saturating_add(covered_bytes);
            self.below_top_frame_bytes.push(covered_bytes);
            if let Some(saved) = &top.saved_scope_chain {
                cold.register_frames(saved);
            }
            let previous = self.below_top_super_winner.last().copied().flatten();
            let top_index = self.frames.len() - 1;
            let winner = if top.super_home_object.is_some()
                && previous.is_none_or(|index| top.super_label > self.frames[index].super_label)
            {
                Some(top_index)
            } else {
                previous
            };
            self.below_top_super_winner.push(winner);
        }
        self.frames.push(frame);
        self.top_bytes.set(None);
    }

    /// The `super_label` of the first frame with the strictly greatest one
    /// among the frames that carry a HomeObject, bottom-up.
    #[inline]
    fn super_label_winner(&self) -> Option<&Label> {
        let below = self
            .below_top_super_winner
            .last()
            .copied()
            .flatten()
            .map(|index| &self.frames[index].super_label);
        match self.frames.last() {
            Some(top)
                if top.super_home_object.is_some()
                    && below.is_none_or(|label| &top.super_label > label) =>
            {
                Some(&top.super_label)
            }
            _ => below,
        }
    }

    fn pop(&mut self, cold: &mut ColdBindingCells) -> Option<CallFrame> {
        let frame = self.frames.pop()?;
        self.top_bytes.set(None);
        if let Some(top) = self.frames.last() {
            self.below_top_super_winner.pop();
            let bytes = self
                .below_top_frame_bytes
                .pop()
                .unwrap_or_else(|| InterpreterCore::estimate_live_call_frame_bytes(top));
            debug_assert_eq!(
                bytes,
                InterpreterCore::estimate_live_call_frame_bytes(top),
                "a covered frame's estimate changed under the frame above it (bd-9vouw.497)"
            );
            debug_assert!(
                self.below_top_bytes >= bytes,
                "call-stack running total lost a frame (bd-9vouw.72)"
            );
            self.below_top_bytes = self.below_top_bytes.saturating_sub(bytes);
            self.top_bytes.set(Some(bytes));
            if let Some(saved) = &top.saved_scope_chain {
                cold.release_frames(saved);
            }
        }
        Some(frame)
    }

    /// Remove and return every frame.
    fn take(&mut self, cold: &mut ColdBindingCells) -> Vec<CallFrame> {
        if let Some((_, below_top)) = self.frames.split_last() {
            for frame in below_top {
                if let Some(saved) = &frame.saved_scope_chain {
                    cold.release_frames(saved);
                }
            }
        }
        self.below_top_bytes = 0;
        self.below_top_frame_bytes.clear();
        self.top_bytes.set(None);
        self.below_top_super_winner.clear();
        std::mem::take(&mut self.frames)
    }

    fn clear(&mut self, cold: &mut ColdBindingCells) {
        drop(self.take(cold));
    }

    fn replace(&mut self, frames: Vec<CallFrame>, cold: &mut ColdBindingCells) {
        self.clear(cold);
        for frame in frames {
            self.push(frame, cold);
        }
    }

    /// The top frame is measured on demand, so it may change in place.
    fn last_mut(&mut self) -> Option<&mut CallFrame> {
        self.top_bytes.set(None);
        self.frames.last_mut()
    }
}

// ---------------------------------------------------------------------------
// Interpreter hooks
// ---------------------------------------------------------------------------

pub type ExtensionId = String;
pub type ObjectRef = ObjectId;
/// Legacy well-formed string property key accepted by
/// [`InterpreterHook::pre_property_access`].
pub type PropertyKey = String;

/// Exact property-key identity presented to interpreter hooks.
///
/// This type is deliberately distinct from the legacy [`PropertyKey`] alias:
/// a `Symbol` never crosses the compatibility callback as a display string,
/// and a non-well-formed ECMAScript string retains its exact UTF-16 units.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HookPropertyKey {
    String(JsString),
    Symbol(SymbolId),
}

impl HookPropertyKey {
    /// Borrow the frozen legacy callback key when that view is lossless.
    pub fn as_legacy_str(&self) -> Result<&str, HookPropertyKeyCompatibilityError> {
        match self {
            Self::String(key) => key
                .as_str()
                .ok_or(HookPropertyKeyCompatibilityError::NonWellFormedString),
            Self::Symbol(_) => Err(HookPropertyKeyCompatibilityError::Symbol),
        }
    }

    /// Convert to the frozen legacy callback key when that conversion is
    /// lossless.
    pub fn to_legacy_property_key(&self) -> Result<PropertyKey, HookPropertyKeyCompatibilityError> {
        self.as_legacy_str().map(ToOwned::to_owned)
    }
}

/// Why the default typed-key adapter cannot call a legacy string-only hook.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HookPropertyKeyCompatibilityError {
    NonWellFormedString,
    Symbol,
}

impl fmt::Display for HookPropertyKeyCompatibilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonWellFormedString => {
                write!(
                    f,
                    "non-well-formed ECMAScript string property key is not representable by the legacy string hook"
                )
            }
            Self::Symbol => {
                write!(
                    f,
                    "Symbol property key is not representable by the legacy string hook"
                )
            }
        }
    }
}

impl std::error::Error for HookPropertyKeyCompatibilityError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeToken {
    pub token: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AllocKind {
    Object,
    Array,
    Function,
    Closure,
    RegExp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookContext {
    pub extension_id: ExtensionId,
    pub instruction_count: u64,
    pub current_ip: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FunctionRef {
    Function {
        function_index: u32,
        name: Option<String>,
    },
    Closure {
        closure_id: u32,
        function_index: u32,
        name: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HookAction {
    Allow,
    Challenge(ChallengeToken),
    Sandbox,
    Suspend,
    Terminate(String),
    Quarantine(String),
}

/// A signed evidence record for runtime guardplane decisions.
/// Provides tamper-evident chain of custody for all containment actions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionReceipt {
    /// Extension that triggered the decision.
    pub extension_id: ExtensionId,
    /// Type of operation that was evaluated.
    pub operation_type: String,
    /// Bayesian risk score (posterior probability of malicious behavior).
    pub risk_score: i64,
    /// Containment action that was taken.
    pub action_taken: String,
    /// Unix timestamp when decision was made.
    pub timestamp: u64,
    /// Instruction pointer at time of decision.
    pub instruction_pointer: usize,
    /// Hash of register state for reproducibility.
    pub register_state_hash: String,
    /// Hash of the previous receipt in the chain (for integrity).
    pub previous_receipt_hash: Option<String>,
    /// HMAC signature for tamper detection.
    pub signature: String,
}

/// Append-only log of decision receipts with hash-chaining for integrity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceLog {
    /// Chain of decision receipts.
    receipts: Vec<DecisionReceipt>,
    /// HMAC key for signing receipts.
    signing_key: [u8; 32],
    /// Counter for generating unique receipt IDs.
    receipt_counter: u64,
}

impl EvidenceLog {
    /// Create a new evidence log with a random signing key.
    pub fn new() -> Self {
        Self {
            receipts: Vec::new(),
            signing_key: Self::generate_signing_key(),
            receipt_counter: 0,
        }
    }

    /// Create evidence log with a specific signing key (for testing).
    pub fn with_key(key: [u8; 32]) -> Self {
        Self {
            receipts: Vec::new(),
            signing_key: key,
            receipt_counter: 0,
        }
    }

    /// Add a new decision receipt to the chain.
    ///
    /// `timestamp` is a caller-supplied deterministic clock value (typically
    /// the interpreter's `instructions_executed` counter). The previous
    /// implementation read `SystemTime::now().as_secs()` here, which made
    /// the receipt-chain HMAC preimage wall-clock-dependent — a replay at
    /// a different real-time produced a different signature even for
    /// byte-identical extension input, breaking the replay-determinism
    /// contract from `AGENTS.md` and rendering receipt chains unverifiable
    /// across replays (bd-jn3uv.1, sibling of bd-jn3uv which fixed the
    /// guardplane-side). Callers from non-deterministic surfaces (e.g.
    /// the `frankenctl evidence export` path that wants wall-clock
    /// stamping) MUST adapt to inject their own clock value; the engine no
    /// longer reaches for `SystemTime` here.
    #[allow(clippy::too_many_arguments)]
    pub fn add_receipt(
        &mut self,
        extension_id: ExtensionId,
        operation_type: String,
        risk_score: i64,
        action_taken: String,
        instruction_pointer: usize,
        register_state: &[Value],
        timestamp: u64,
    ) -> &DecisionReceipt {
        let register_state_hash = self.compute_register_hash(register_state);
        let previous_receipt_hash = self.receipts.last().map(|r| r.signature.clone());

        // Create unsigned receipt
        let mut receipt = DecisionReceipt {
            extension_id,
            operation_type,
            risk_score,
            action_taken,
            timestamp,
            instruction_pointer,
            register_state_hash,
            previous_receipt_hash,
            signature: String::new(), // Will be filled by signing
        };

        // Sign the receipt
        receipt.signature = self.sign_receipt(&receipt);

        self.receipts.push(receipt);
        self.receipt_counter += 1;

        // SAFETY: We just pushed a receipt above, so receipts is non-empty and last() cannot return None
        self.receipts
            .last()
            .expect("receipt chain should have at least one entry after push")
    }

    /// Verify the integrity of the entire receipt chain.
    pub fn verify_chain(&self) -> bool {
        for (i, receipt) in self.receipts.iter().enumerate() {
            // Verify receipt signature
            if !self.verify_receipt_signature(receipt) {
                return false;
            }

            // Verify chain linking
            if i > 0 {
                let expected_prev_hash = &self.receipts[i - 1].signature;
                if receipt.previous_receipt_hash.as_ref() != Some(expected_prev_hash) {
                    return false;
                }
            } else if receipt.previous_receipt_hash.is_some() {
                return false; // First receipt should have no previous hash
            }
        }

        true
    }

    /// Export receipts as JSON evidence bundle.
    pub fn export_json(&self) -> Result<String, serde_json::Error> {
        let bundle = serde_json::json!({
            "evidence_type": "guardplane_decision_chain",
            "receipt_count": self.receipts.len(),
            "chain_verified": self.verify_chain(),
            "receipts": self.receipts,
            "exported_at": SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        });

        serde_json::to_string_pretty(&bundle)
    }

    /// Get all receipts in the chain.
    pub fn receipts(&self) -> &[DecisionReceipt] {
        &self.receipts
    }

    /// Check if log is empty (no decisions made).
    pub fn is_empty(&self) -> bool {
        self.receipts.is_empty()
    }

    /// Generate a fresh 256-bit HMAC signing key from the operating-system
    /// CSPRNG (bd-7r0ty).
    ///
    /// Previously the key was constructed from `SystemTime::now().as_nanos()`
    /// with bytes 16..=31 replicating bytes 0..=15, yielding at most 128 bits
    /// of source entropy and as little as ~30 bits of *practical* entropy when
    /// the construction moment could be bounded to a one-second window —
    /// trivially recoverable by an attacker who could approximate when the
    /// `EvidenceLog` was constructed, which forged the entire downstream
    /// receipt chain. The new construction reads 32 random bytes from
    /// `rand::rngs::OsRng` (same source `revocation_freshness` and
    /// `secure_aggregation` already use), so every byte of the key carries
    /// 8 bits of entropy. Tests that need a deterministic key continue to use
    /// [`EvidenceLog::with_key`].
    fn generate_signing_key() -> [u8; 32] {
        use rand::RngCore;
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        key
    }

    /// Compute HMAC signature for a receipt.
    fn sign_receipt(&self, receipt: &DecisionReceipt) -> String {
        let message = self.receipt_signing_message(receipt);
        self.compute_hmac(&message)
    }

    /// Verify HMAC signature of a receipt.
    fn verify_receipt_signature(&self, receipt: &DecisionReceipt) -> bool {
        let message = self.receipt_signing_message(receipt);
        let expected_signature = self.compute_hmac(&message);
        receipt
            .signature
            .as_bytes()
            .ct_eq(expected_signature.as_bytes())
            .into()
    }

    /// Build the binary signing preimage for a receipt (bd-gn3mt).
    ///
    /// The previous implementation joined fields with `|` characters:
    ///
    /// ```text
    /// "{extension_id}|{operation_type}|{risk_score}|{action_taken}|…"
    /// ```
    ///
    /// That preimage was vulnerable to field-boundary smuggling — an attacker
    /// who could place a `|` byte inside any variable-length field
    /// (`extension_id`, `operation_type`, `action_taken`, `register_state_hash`,
    /// `previous_receipt_hash`) could shift the semantic field boundaries so
    /// a downstream verifier that split on `|` saw an entirely different
    /// receipt (e.g. action_taken="GRANT_ADMIN" smuggled through extension_id).
    ///
    /// The replacement mirrors the established
    /// [`crate::tee_attestation_policy::AttestationQuote::signing_preimage`]
    /// pattern: a fixed leading domain-separation tag (so the same HMAC key
    /// cannot collide with any other receipt class), a `0xff` sentinel between
    /// the tag and the first field, and a 64-bit big-endian length prefix in
    /// front of every variable-length string field. Numeric fields are
    /// serialised as fixed-width big-endian byte sequences so they cannot
    /// shrink into a neighbour. The `previous_receipt_hash` `Option<String>`
    /// is encoded as a one-byte present/absent tag followed by an optional
    /// length-prefixed payload.
    fn receipt_signing_message(&self, receipt: &DecisionReceipt) -> Vec<u8> {
        fn push_len_prefixed(buf: &mut Vec<u8>, bytes: &[u8]) {
            buf.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            buf.extend_from_slice(bytes);
        }

        let mut preimage = Vec::with_capacity(256);
        preimage.extend_from_slice(RECEIPT_SIGNATURE_DOMAIN);
        preimage.push(0xff);
        push_len_prefixed(&mut preimage, receipt.extension_id.as_bytes());
        push_len_prefixed(&mut preimage, receipt.operation_type.as_bytes());
        preimage.extend_from_slice(&receipt.risk_score.to_be_bytes());
        push_len_prefixed(&mut preimage, receipt.action_taken.as_bytes());
        preimage.extend_from_slice(&receipt.timestamp.to_be_bytes());
        preimage.extend_from_slice(&(receipt.instruction_pointer as u64).to_be_bytes());
        push_len_prefixed(&mut preimage, receipt.register_state_hash.as_bytes());
        match receipt.previous_receipt_hash.as_deref() {
            Some(prev) => {
                preimage.push(1);
                push_len_prefixed(&mut preimage, prev.as_bytes());
            }
            None => {
                preimage.push(0);
            }
        }
        preimage
    }

    /// Compute HMAC-SHA256 of a binary message.
    fn compute_hmac(&self, message: &[u8]) -> String {
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(&self.signing_key).unwrap_or_else(|_| {
                panic!("32-byte signing key should always be valid for HMAC-SHA256")
            });
        mac.update(message);
        format!("hmac-sha256-{}", hex::encode(mac.finalize().into_bytes()))
    }

    /// Compute hash of register state for reproducibility.
    fn compute_register_hash(&self, registers: &[Value]) -> String {
        let mut hasher_state = 0u64;

        for value in registers {
            // Simple hash of value discriminant + content
            let value_hash = match value {
                Value::Undefined => 0,
                Value::Null => 1,
                Value::Bool(b) => 2 + (*b as u64),
                Value::Int(i) => 4 + (*i as u64),
                Value::Float(f) => 4 + f.0.to_bits(),
                Value::BigInt(n) => {
                    let mut bigint_hash = 18u64;
                    for byte in n.bytes() {
                        bigint_hash = bigint_hash.wrapping_mul(31).wrapping_add(byte as u64);
                    }
                    bigint_hash
                }
                Value::Str(s) => {
                    if s.is_well_formed() {
                        // Well-formed strings keep the historical UTF-8 byte
                        // fold, so existing register hashes are unchanged.
                        let mut string_hash = 5u64;
                        for byte in s.bytes() {
                            string_hash = string_hash.wrapping_mul(31).wrapping_add(byte as u64);
                        }
                        string_hash
                    } else {
                        // Lone-surrogate content folds its exact code units
                        // under a distinct seed: distinct lone surrogates must
                        // not collapse to the shared U+FFFD projection hash
                        // (bd-neika).
                        let mut string_hash = 21u64;
                        for unit in s.encode_utf16() {
                            string_hash =
                                string_hash.wrapping_mul(31).wrapping_add(u64::from(unit));
                        }
                        string_hash
                    }
                }
                Value::Object(id) => 6 + (id.0 as u64),
                Value::Function(id) => 7 + (*id as u64),
                Value::Closure(id) => 8 + (*id as u64),
                Value::Iterator(id) => 9 + (*id as u64),
                Value::GeneratorFunction(id) => 10 + (*id as u64),
                Value::Generator(id) => 11 + (*id as u64),
                Value::AsyncFunction(id) => 12 + (*id as u64),
                Value::AsyncFunctionObject(id) => 13 + (*id as u64),
                Value::AsyncGeneratorFunction(id) => 14 + (*id as u64),
                Value::AsyncGeneratorObject(id) => 15 + (*id as u64),
                Value::Promise(id) => 16 + (*id as u64),
                Value::BuiltinFunction(bf) => Self::hash_builtin_function_seed(bf),
                Value::Accessor { get, set } => {
                    let get_hash = get
                        .as_deref()
                        .map(Self::hash_register_value_seed)
                        .unwrap_or(0);
                    let set_hash = set
                        .as_deref()
                        .map(Self::hash_register_value_seed)
                        .unwrap_or(0);
                    19u64
                        .wrapping_add(get_hash.wrapping_mul(31))
                        .wrapping_add(set_hash)
                }
                Value::Symbol(symbol) => 20 + u64::from(symbol.0),
            };
            hasher_state = hasher_state.wrapping_mul(31).wrapping_add(value_hash);
        }

        format!("reghash-{:016x}", hasher_state)
    }

    fn hash_register_value_seed(value: &Value) -> u64 {
        match value {
            Value::Undefined => 0,
            Value::Null => 1,
            Value::Bool(b) => 2 + (*b as u64),
            Value::Int(i) => 4 + (*i as u64),
            Value::Float(f) => 4 + f.0.to_bits(),
            Value::BigInt(n) => n.bytes().fold(18u64, |acc, byte| {
                acc.wrapping_mul(31).wrapping_add(byte as u64)
            }),
            Value::Str(s) => s.bytes().fold(5u64, |acc, byte| {
                acc.wrapping_mul(31).wrapping_add(byte as u64)
            }),
            Value::Object(id) => 6 + (id.0 as u64),
            Value::Function(id) => 7 + (*id as u64),
            Value::Closure(id) => 8 + (*id as u64),
            Value::Iterator(id) => 9 + (*id as u64),
            Value::GeneratorFunction(id) => 10 + (*id as u64),
            Value::Generator(id) => 11 + (*id as u64),
            Value::AsyncFunction(id) => 12 + (*id as u64),
            Value::AsyncFunctionObject(id) => 13 + (*id as u64),
            Value::AsyncGeneratorFunction(id) => 14 + (*id as u64),
            Value::AsyncGeneratorObject(id) => 15 + (*id as u64),
            Value::Promise(id) => 16 + (*id as u64),
            Value::BuiltinFunction(bf) => Self::hash_builtin_function_seed(bf),
            Value::Accessor { get, set } => {
                let get_hash = get
                    .as_deref()
                    .map(Self::hash_register_value_seed)
                    .unwrap_or(0);
                let set_hash = set
                    .as_deref()
                    .map(Self::hash_register_value_seed)
                    .unwrap_or(0);
                19u64
                    .wrapping_add(get_hash.wrapping_mul(31))
                    .wrapping_add(set_hash)
            }
            Value::Symbol(symbol) => 20 + u64::from(symbol.0),
        }
    }

    fn hash_builtin_function_seed(builtin: &BuiltinFunction) -> u64 {
        let module_hash = if builtin.module_specifier.is_empty() {
            0
        } else {
            builtin.module_specifier.bytes().fold(23u64, |state, byte| {
                state.wrapping_mul(31).wrapping_add(u64::from(byte))
            })
        };
        17u64
            .wrapping_add(builtin.kind as u64)
            .wrapping_add(builtin.iterator_handle.map(u64::from).unwrap_or(0))
            .wrapping_add(builtin.bound_object.map(u64::from).unwrap_or(0))
            .wrapping_add(module_hash)
    }
}

impl Default for EvidenceLog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod evidence_log_signing_key_tests {
    //! bd-7r0ty: the production signing key used to be built from
    //! `SystemTime::now().as_nanos()` with bytes 16..=31 mirroring bytes 0..=15,
    //! yielding at most 128 bits of source entropy and as few as ~30 bits of
    //! practical entropy when the construction moment was observable. The
    //! switch to `OsRng` removes both defects; these tests pin the new
    //! invariants so a regression is impossible to reintroduce silently.

    use super::*;

    #[test]
    fn signing_key_is_not_byte_repetitive() {
        // Two independently-constructed logs MUST produce different keys.
        // Collision probability with OsRng on 32 bytes is 2^-256, well below
        // any realistic flake threshold.
        let log_a = EvidenceLog::new();
        let log_b = EvidenceLog::new();
        assert_ne!(
            log_a.signing_key, log_b.signing_key,
            "OsRng-derived keys must be distinct across constructions",
        );

        // A single key must NOT have bytes 16..=31 mirror bytes 0..=15 — the
        // exact pattern the bd-7r0ty pre-fix `SystemTime`-derived construction
        // produced.
        let key = log_a.signing_key;
        assert_ne!(
            &key[0..16],
            &key[16..32],
            "bytes 16..=31 must not mirror bytes 0..=15 (bd-7r0ty regression)",
        );

        // Sanity: not every byte equal — a zeroed/all-same key would still
        // satisfy the mirror check above. OsRng draws are uniform over
        // u8::MIN..=u8::MAX so the probability of all-same bytes is 256/256^32.
        assert!(
            key.iter().any(|&b| b != key[0]),
            "key must contain at least two distinct byte values",
        );
    }

    /// bd-gn3mt regression guard: a `|` character inserted inside any
    /// variable-length string field MUST NOT yield a preimage that equals the
    /// preimage of some *legitimate* receipt with different semantic field
    /// values. The pre-fix construction used `format!("{}|{}|{}…", …)` which
    /// allowed an attacker who controlled `extension_id` to embed `|read|0|`
    /// and shift the field boundary so a downstream `|`-splitting verifier
    /// saw a different receipt. The new construction prefixes every variable
    /// field with its `u64::to_be_bytes()` length, so the boundaries are
    /// pinned by the prefix, not by an in-band delimiter.
    #[test]
    fn receipt_signing_preimage_resists_pipe_smuggling() {
        let key = [0x42u8; 32];
        let log = EvidenceLog::with_key(key);

        let legitimate = DecisionReceipt {
            extension_id: "legitimate-ext".to_string(),
            operation_type: "read".to_string(),
            risk_score: 0,
            action_taken: "ALLOW".to_string(),
            timestamp: 1000,
            instruction_pointer: 42,
            register_state_hash: "abc".to_string(),
            previous_receipt_hash: Some("xyz".to_string()),
            signature: String::new(),
        };

        let smuggled = DecisionReceipt {
            extension_id: "legitimate-ext|read|0|ALLOW".to_string(),
            operation_type: String::new(),
            risk_score: 0,
            action_taken: String::new(),
            timestamp: 1000,
            instruction_pointer: 42,
            register_state_hash: "abc".to_string(),
            previous_receipt_hash: Some("xyz".to_string()),
            signature: String::new(),
        };

        let pre_legit = log.receipt_signing_message(&legitimate);
        let pre_smug = log.receipt_signing_message(&smuggled);

        assert_ne!(
            pre_legit, pre_smug,
            "bd-gn3mt: pipe-bearing extension_id must NOT collide with the canonical preimage",
        );
        // And the HMACs must differ, which is what the verifier actually checks.
        assert_ne!(
            log.sign_receipt(&legitimate),
            log.sign_receipt(&smuggled),
            "bd-gn3mt: HMAC of pipe-bearing extension_id must differ from canonical HMAC",
        );
    }

    /// bd-gn3mt regression guard: the preimage MUST start with the
    /// domain-separation tag. Without it, an HMAC signed for an attestation
    /// quote (which uses `FrankenEngine.AttestationQuote.Signature.v1`)
    /// or any other future signed-message type could collide with a receipt
    /// HMAC under the same key.
    #[test]
    fn receipt_signing_preimage_starts_with_domain_tag() {
        let log = EvidenceLog::with_key([0x33u8; 32]);
        let receipt = DecisionReceipt {
            extension_id: "ext".to_string(),
            operation_type: "op".to_string(),
            risk_score: 0,
            action_taken: "ALLOW".to_string(),
            timestamp: 0,
            instruction_pointer: 0,
            register_state_hash: String::new(),
            previous_receipt_hash: None,
            signature: String::new(),
        };
        let preimage = log.receipt_signing_message(&receipt);
        assert!(
            preimage.starts_with(RECEIPT_SIGNATURE_DOMAIN),
            "preimage must start with the domain-separation tag",
        );
        // The domain tag must end with the 0xff separator so the first
        // length-prefixed field's leading length byte cannot be misread as
        // tag text.
        assert_eq!(
            preimage[RECEIPT_SIGNATURE_DOMAIN.len()],
            0xff,
            "0xff separator must immediately follow the domain tag",
        );
    }

    /// bd-gn3mt regression guard: the preimage encodes Option<String>
    /// (previous_receipt_hash) with an explicit 1-byte present/absent tag, so
    /// `Some("")` and `None` MUST produce different preimages — otherwise an
    /// attacker could elide the chain link on a first receipt and re-sign a
    /// non-first receipt with the same preimage.
    #[test]
    fn receipt_signing_preimage_distinguishes_none_from_empty_prev_hash() {
        let log = EvidenceLog::with_key([0x55u8; 32]);
        let base = DecisionReceipt {
            extension_id: "ext".to_string(),
            operation_type: "op".to_string(),
            risk_score: 1,
            action_taken: "ALLOW".to_string(),
            timestamp: 1,
            instruction_pointer: 1,
            register_state_hash: "h".to_string(),
            previous_receipt_hash: None,
            signature: String::new(),
        };
        let with_empty = DecisionReceipt {
            previous_receipt_hash: Some(String::new()),
            ..base.clone()
        };
        assert_ne!(
            log.receipt_signing_message(&base),
            log.receipt_signing_message(&with_empty),
            "None and Some(\"\") for previous_receipt_hash must yield distinct preimages",
        );
    }

    #[test]
    fn signing_key_passes_basic_byte_spread_check() {
        // Quick sanity that the byte distribution looks like CSPRNG output:
        // across 32 bytes from a fresh key, expect at least 16 distinct byte
        // values. (Birthday-collision math: P[< 16 distinct] is negligibly
        // small for uniform 8-bit draws.) Catches a regression where the new
        // construction accidentally collapses entropy to a single byte source.
        let log = EvidenceLog::new();
        let mut seen = std::collections::BTreeSet::new();
        for &b in log.signing_key.iter() {
            seen.insert(b);
        }
        assert!(
            seen.len() >= 16,
            "expected >=16 distinct byte values from a CSPRNG-derived 32-byte key, got {} \
             (key bytes: {:?})",
            seen.len(),
            log.signing_key,
        );
    }
}

/// `pre_import` is part of the stable hook contract and is invoked on
/// `ImportModule` during module loading.
pub trait InterpreterHook: Send + Sync {
    /// Whether this hook observes guest instruction activity in addition to
    /// live hostcall decisions. Existing hooks retain their full contract.
    /// Effects-only hooks skip instruction callbacks and their legacy key ABI;
    /// this never suppresses the capability membrane or `pre_hostcall`.
    fn instruction_hooks_enabled(&self) -> bool {
        true
    }

    /// Frozen compatibility callback for well-formed string property keys.
    ///
    /// New implementations that need exact strings or Symbols should override
    /// [`InterpreterHook::pre_property_access_typed`]. The default typed
    /// adapter calls this method only when conversion is lossless.
    fn pre_property_access(
        &self,
        ctx: &HookContext,
        target: &ObjectRef,
        key: &PropertyKey,
    ) -> HookAction;

    /// Typed property callback used by executable object property operations.
    ///
    /// The default implementation preserves existing hook implementations:
    /// well-formed strings reach [`InterpreterHook::pre_property_access`],
    /// while Symbols and non-well-formed strings fail closed without invoking
    /// that legacy callback.
    fn pre_property_access_typed(
        &self,
        ctx: &HookContext,
        target: &ObjectRef,
        key: &HookPropertyKey,
    ) -> Result<HookAction, HookPropertyKeyCompatibilityError> {
        let legacy_key = key.to_legacy_property_key()?;
        Ok(self.pre_property_access(ctx, target, &legacy_key))
    }

    fn pre_call(&self, ctx: &HookContext, callee: &FunctionRef, args: &[Value]) -> HookAction;

    fn pre_allocation(&self, ctx: &HookContext, kind: AllocKind, size_hint: usize) -> HookAction;

    fn pre_import(&self, ctx: &HookContext, specifier: &str) -> HookAction;

    /// Observe the live capability decision before any hostcall effect.
    /// `allowed` reports the existing capability membrane; returning Allow
    /// never overrides a denial. Non-Allow stops an authorized dispatch.
    fn pre_hostcall(&self, _ctx: &HookContext, _capability: &str, _allowed: bool) -> HookAction {
        HookAction::Allow
    }
}

// ---------------------------------------------------------------------------
// ModuleResolutionFailureReason
// ---------------------------------------------------------------------------

/// Specific reasons for module resolution failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModuleResolutionFailureReason {
    /// Bare specifiers are not supported in the current resolution context:
    /// ESM `import` of a package, or a `require` with no module root to bound
    /// the `node_modules` search.
    BareSpecifiersNotSupported,
    /// Specifier format is malformed or invalid.
    MalformedSpecifier,
    /// Module not found in resolution paths.
    ModuleNotFound,
    /// The captured package exports map does not expose this subpath.
    PackagePathNotExported,
    /// The captured package scope has no matching private imports mapping.
    PackageImportNotDefined,
    /// The selected file is a native addon, for which this runtime has no
    /// admitted loader. Its bytes must never be parsed as JavaScript.
    NativeAddonUnsupported,
    /// Other resolution failure with descriptive reason.
    Other(String),
}

impl ModuleResolutionFailureReason {
    pub fn as_str(&self) -> &str {
        match self {
            Self::BareSpecifiersNotSupported => "bare specifiers not supported",
            Self::MalformedSpecifier => "malformed specifier",
            Self::ModuleNotFound => "module not found",
            Self::PackagePathNotExported => "package subpath is not exported",
            Self::PackageImportNotDefined => "package import is not defined",
            Self::NativeAddonUnsupported => "native addons are not supported",
            Self::Other(_) => "resolution failed",
        }
    }

    /// Only these source-resolution outcomes are guest control flow. A
    /// capability-policy denial, uncaptured route or invalid referrer is not.
    fn from_captured_code(code: ResolutionErrorCode) -> Option<Self> {
        match code {
            ResolutionErrorCode::ModuleNotFound => Some(Self::ModuleNotFound),
            ResolutionErrorCode::PackagePathNotExported => Some(Self::PackagePathNotExported),
            ResolutionErrorCode::PackageImportNotDefined => Some(Self::PackageImportNotDefined),
            _ => None,
        }
    }

    fn guest_error_code(&self, style: ImportStyle) -> &'static str {
        match self {
            Self::PackagePathNotExported => "ERR_PACKAGE_PATH_NOT_EXPORTED",
            Self::PackageImportNotDefined => "ERR_PACKAGE_IMPORT_NOT_DEFINED",
            Self::NativeAddonUnsupported => "ERR_DLOPEN_DISABLED",
            _ if style == ImportStyle::Import => "ERR_MODULE_NOT_FOUND",
            _ => "MODULE_NOT_FOUND",
        }
    }
}

impl fmt::Display for ModuleResolutionFailureReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BareSpecifiersNotSupported => write!(f, "bare specifiers not supported"),
            Self::MalformedSpecifier => write!(f, "malformed specifier"),
            Self::ModuleNotFound => write!(f, "module not found"),
            Self::PackagePathNotExported => write!(f, "package subpath is not exported"),
            Self::PackageImportNotDefined => write!(f, "package import is not defined"),
            Self::NativeAddonUnsupported => write!(f, "native addons are not supported"),
            Self::Other(reason) => write!(f, "{}", reason),
        }
    }
}

// InterpreterError
// ---------------------------------------------------------------------------

/// Errors from the baseline interpreter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InterpreterError {
    /// Instruction budget exhausted.
    BudgetExhausted { executed: u64, budget: u64 },
    /// Register index out of bounds.
    RegisterOutOfBounds { register: u32, max: u32 },
    /// Instruction pointer out of bounds.
    InstructionOutOfBounds { ip: usize, count: usize },
    /// Call stack overflow.
    StackOverflow { depth: usize, max: usize },
    /// Type error (e.g. adding object + bool).
    TypeError { expected: String, got: String },
    /// Range error (e.g. invalid normalize form).
    RangeError { message: String },
    /// Division by zero.
    DivisionByZero,
    /// Undefined variable (register not initialized).
    UndefinedRegister { register: u32 },
    /// Object not found on heap.
    ObjectNotFound { id: u32 },
    /// Property not found on object.
    PropertyNotFound { object_id: u32, key: String },
    /// Function not found in table.
    FunctionNotFound { index: u32, table_size: u32 },
    /// String pool index out of bounds.
    StringPoolOutOfBounds { index: u32, pool_size: u32 },
    /// Import specifier register did not contain a string.
    ImportSpecifierNotString { got: String },
    /// Require specifier register did not contain a string.
    RequireSpecifierNotString { got: String },
    /// Module resolution failed.
    ModuleResolutionFailed {
        specifier: String,
        reason: ModuleResolutionFailureReason,
    },
    /// Failed to read module source from disk.
    ModuleReadFailed { specifier: String, error: String },
    /// Failed to parse module source.
    ModuleParseFailed { specifier: String, error: String },
    /// Failed to lower module source to IR3.
    ModuleLoweringFailed { specifier: String, error: String },
    /// Module evaluation failed.
    ModuleEvaluationFailed { specifier: String, reason: String },
    /// Export encountered outside an active module evaluation.
    ExportOutsideModule { name: String },
    /// Capability check failed for hostcall.
    CapabilityDenied { capability: String },
    /// Guest-visible filesystem error preserving a stable Node-style code.
    HostFilesystem { code: String, message: String },
    /// Guest-visible child-process failure with Node-style structured output.
    HostProcess {
        code: String,
        message: String,
        status: Option<i32>,
        signal: Option<i32>,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    },
    /// The baseline heap cannot safely answer prototype-aware membership.
    UnsupportedMembershipSemantics { operator: String },
    /// Iterator handle not found in interpreter state.
    IteratorNotFound { handle: u32 },
    /// Halt instruction reached (normal termination).
    Halted,
    /// An exception was thrown but no catch handler was found.
    UncaughtException { value: String },
    /// Access to a let/const binding before initialization (TDZ).
    UninitializedBinding { name: String },
    /// A dynamically resolved name was absent from every visible environment.
    UndefinedBinding { name: String },
    /// Assignment to a const binding.
    ConstAssignment { name: String },
    /// String allocation size exceeded.
    StringLimitExceeded { length: usize, max: usize },
    /// Heap object count or estimated live memory exceeded configured limits.
    MemoryBudgetExceeded {
        requested_bytes: u64,
        max_bytes: u64,
        requested_heap_objects: u32,
        max_heap_objects: u32,
    },
    /// Scope-chain depth exceeded configured limits.
    ScopeDepthExceeded {
        requested_depth: usize,
        max_depth: usize,
    },
    /// The program printed more console output than the run may retain.
    /// Fails the run instead of dropping output: `entries`/`bytes` are what
    /// retaining the refused entry would have required.
    ConsoleBudgetExceeded {
        entries: usize,
        max_entries: usize,
        bytes: usize,
        max_bytes: usize,
    },
    /// Internal invariant violation detected in interpreter state.
    InternalError { details: String },
    /// Guardplane containment hook requested a fail-closed action.
    ContainmentActionRequested {
        action: String,
        reason: Option<String>,
    },
    /// Execution terminated by containment action.
    Terminated { reason: String },
    /// The program called `process.exit(code)` (bd-my9hk). Not catchable and
    /// runs no `finally` block, pending callback or microtask, as in Node;
    /// the top level turns it into a completed run with that exit code.
    ProcessExit { code: i32 },
    /// Execution cancelled by CheckpointGuard.
    Cancelled,
}

impl fmt::Display for InterpreterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BudgetExhausted { executed, budget } => {
                write!(f, "instruction budget exhausted: {executed}/{budget}")
            }
            Self::RegisterOutOfBounds { register, max } => {
                write!(f, "register {register} out of bounds (max {max})")
            }
            Self::InstructionOutOfBounds { ip, count } => {
                write!(
                    f,
                    "instruction pointer {ip} out of bounds ({count} instructions)"
                )
            }
            Self::StackOverflow { depth, max } => {
                write!(f, "call stack overflow: depth {depth} exceeds max {max}")
            }
            Self::TypeError { expected, got } => {
                write!(f, "type error: expected {expected}, got {got}")
            }
            Self::RangeError { message } => write!(f, "range error: {message}"),
            Self::DivisionByZero => write!(f, "division by zero"),
            Self::UndefinedRegister { register } => {
                write!(f, "undefined register r{register}")
            }
            Self::ObjectNotFound { id } => write!(f, "object#{id} not found"),
            Self::PropertyNotFound { object_id, key } => {
                write!(f, "property '{key}' not found on object#{object_id}")
            }
            Self::FunctionNotFound { index, table_size } => {
                write!(f, "function#{index} not found (table size {table_size})")
            }
            Self::StringPoolOutOfBounds { index, pool_size } => {
                write!(
                    f,
                    "string pool index {index} out of bounds (pool size {pool_size})"
                )
            }
            Self::ImportSpecifierNotString { got } => {
                write!(f, "import specifier must be string (got {got})")
            }
            Self::RequireSpecifierNotString { got } => {
                write!(f, "require specifier must be string (got {got})")
            }
            Self::ModuleResolutionFailed { specifier, reason } => {
                write!(f, "module resolution failed for '{specifier}': {reason}")
            }
            Self::ModuleReadFailed { specifier, error } => {
                write!(f, "failed to read module '{specifier}': {error}")
            }
            Self::ModuleParseFailed { specifier, error } => {
                write!(f, "failed to parse module '{specifier}': {error}")
            }
            Self::ModuleLoweringFailed { specifier, error } => {
                write!(f, "failed to lower module '{specifier}': {error}")
            }
            Self::ModuleEvaluationFailed { specifier, reason } => {
                write!(f, "module '{specifier}' evaluation failed: {reason}")
            }
            Self::ExportOutsideModule { name } => {
                write!(f, "export '{name}' outside of module evaluation")
            }
            Self::CapabilityDenied { capability } => {
                write!(f, "capability denied: {capability}")
            }
            Self::HostFilesystem { code, message } => {
                write!(f, "filesystem error {code}: {message}")
            }
            Self::HostProcess { code, message, .. } => {
                write!(f, "child process error {code}: {message}")
            }
            Self::UnsupportedMembershipSemantics { operator } => write!(
                f,
                "unsupported {operator} semantics: baseline interpreter heap is not prototype-aware"
            ),
            Self::IteratorNotFound { handle } => write!(f, "iterator#{handle} not found"),
            Self::Halted => write!(f, "execution halted"),
            Self::Cancelled => write!(f, "execution cancelled"),
            Self::UncaughtException { value } => {
                write!(f, "uncaught exception: {value}")
            }
            Self::UninitializedBinding { name } => {
                write!(
                    f,
                    "cannot access '{name}' before initialization (temporal dead zone)"
                )
            }
            Self::UndefinedBinding { name } => {
                write!(f, "{name} is not defined")
            }
            Self::ConstAssignment { name } => {
                write!(f, "assignment to constant variable '{name}'")
            }
            Self::StringLimitExceeded { length, max } => {
                write!(
                    f,
                    "string allocation size exceeded ({} bytes > {} bytes)",
                    length, max
                )
            }
            Self::MemoryBudgetExceeded {
                requested_bytes,
                max_bytes,
                requested_heap_objects,
                max_heap_objects,
            } => write!(
                f,
                "memory budget exceeded: requested {} heap objects / {} bytes, limits {} heap objects / {} bytes",
                requested_heap_objects, requested_bytes, max_heap_objects, max_bytes
            ),
            Self::ScopeDepthExceeded {
                requested_depth,
                max_depth,
            } => write!(
                f,
                "scope depth exceeded: requested depth {requested_depth}, limit {max_depth}"
            ),
            Self::ConsoleBudgetExceeded {
                entries,
                max_entries,
                bytes,
                max_bytes,
            } => write!(
                f,
                "console output budget exceeded: {entries} entries / {bytes} bytes, limits {max_entries} entries / {max_bytes} bytes"
            ),
            Self::InternalError { details } => {
                write!(f, "internal interpreter invariant violated: {details}")
            }
            Self::ContainmentActionRequested { action, reason } => {
                if let Some(reason) = reason {
                    write!(f, "containment action requested: {action} ({reason})")
                } else {
                    write!(f, "containment action requested: {action}")
                }
            }
            Self::Terminated { reason } => {
                write!(f, "execution terminated by containment action: {reason}")
            }
            Self::ProcessExit { code } => write!(f, "process.exit({code})"),
        }
    }
}

impl std::error::Error for InterpreterError {}

// ---------------------------------------------------------------------------
// InterpreterConfig — lane-specific configuration
// ---------------------------------------------------------------------------

/// Configuration for an interpreter lane.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterpreterConfig {
    /// Maximum instructions before budget exhaustion.
    pub instruction_budget: u64,
    /// Maximum registers per frame.
    pub max_registers: u32,
    /// Maximum call depth.
    pub max_call_depth: usize,
    /// Maximum string allocation size (bytes).
    pub max_string_size: usize,
    /// Maximum heap objects the interpreter may allocate before failing closed.
    pub max_heap_objects: u32,
    /// Maximum estimated live memory before failing closed.
    pub max_total_memory_bytes: u64,
    /// Maximum console entries a run may retain. One more fails the run with
    /// [`InterpreterError::ConsoleBudgetExceeded`]; output is never dropped
    /// silently. `0` disables console capture altogether.
    pub max_console_entries: usize,
    /// Maximum bytes of console text a run may retain; exceeding it fails the
    /// run with [`InterpreterError::ConsoleBudgetExceeded`].
    #[serde(default = "default_max_console_bytes")]
    pub max_console_bytes: usize,
    /// Maximum scope-chain depth, including the global frame.
    pub max_scope_depth: u32,
    /// Optional module root used for resolving relative import specifiers.
    pub module_root: Option<String>,
    /// Cached canonicalized module root to avoid repeated canonicalization.
    #[serde(skip)]
    pub canonical_module_root: Option<PathBuf>,
    /// Set of capabilities granted to this execution context.
    pub granted_capabilities: BTreeSet<RuntimeCapability>,
    /// Optional extension ID for logging and diagnostics.
    pub extension_id: Option<String>,
    /// Optional cancellation token for checkpoint-based cancellation.
    #[serde(skip)]
    pub cancellation_token: Option<CancellationToken>,
    /// Checkpoint density (default: every 1000 instructions).
    pub checkpoint_density: u64,
    /// The entry program is a host-declared CommonJS module (bd-rff5g): its
    /// root scope receives the wrapper bindings a required module receives.
    /// Only the orchestrator sets this, together with lowering the entry in
    /// the authenticated CommonJS context.
    #[serde(default)]
    pub commonjs_entry: bool,
    /// Parser options (mode and budgets) for every module this interpreter
    /// loads at runtime (`require`, `import`). The orchestrator sets them to
    /// the options the entry was parsed under, so a dependency is held to the
    /// same budget as the program that requires it.
    #[serde(default)]
    pub module_parser_options: ParserOptions,
    /// Additional package imports/exports conditions chosen by the embedder.
    /// These augment `node` and the current `import`/`require` condition;
    /// they never select another loader or grant filesystem authority.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub module_conditions: Vec<String>,
    /// `process.argv` as the embedder launched the program (bd-my9hk):
    /// runtime path, script path, then the program's own arguments. Empty
    /// unless the embedder supplies it.
    #[serde(default)]
    pub process_argv: Vec<String>,
    /// Explicit embedder authority for private native-util argument readers.
    /// This is the runtime counterpart of TrustedProcessShape lowering; a
    /// Builtin grant alone must not authorize access to invocation inputs.
    #[serde(default)]
    pub process_shape_read_allowed: bool,
    /// When true, `Function` / `AsyncFunction` / `GeneratorFunction` /
    /// `AsyncGeneratorFunction` constructors are refused at runtime with
    /// `CapabilityDenied { capability: "eval" }`.
    #[serde(default)]
    pub disallow_dynamic_codegen: bool,
    /// Optional explicit IFC flow policy enforced at runtime sink checks.
    #[serde(default)]
    pub ifc_flow_policy: Option<crate::ifc_artifacts::FlowPolicy>,
    /// Signed declassification receipts consulted when `ifc_flow_policy`
    /// requires an authorized declassification route.
    #[serde(default)]
    pub declassification_receipts: Vec<crate::ifc_artifacts::DeclassificationReceipt>,
}

impl PartialEq for InterpreterConfig {
    fn eq(&self, other: &Self) -> bool {
        self.instruction_budget == other.instruction_budget
            && self.max_registers == other.max_registers
            && self.max_call_depth == other.max_call_depth
            && self.max_string_size == other.max_string_size
            && self.max_heap_objects == other.max_heap_objects
            && self.max_total_memory_bytes == other.max_total_memory_bytes
            && self.max_console_entries == other.max_console_entries
            && self.max_console_bytes == other.max_console_bytes
            && self.max_scope_depth == other.max_scope_depth
            && self.module_root == other.module_root
            && self.granted_capabilities == other.granted_capabilities
            && self.extension_id == other.extension_id
            && self.checkpoint_density == other.checkpoint_density
            && self.module_parser_options == other.module_parser_options
            && self.module_conditions == other.module_conditions
            && self.process_argv == other.process_argv
            && self.process_shape_read_allowed == other.process_shape_read_allowed
            && self.disallow_dynamic_codegen == other.disallow_dynamic_codegen
            && self.ifc_flow_policy == other.ifc_flow_policy
            && self.declassification_receipts == other.declassification_receipts
        // Note: cancellation_token is intentionally excluded from comparison
    }
}

impl Eq for InterpreterConfig {}

impl InterpreterConfig {
    /// Deterministic profile defaults: conservative budgets.
    pub fn quickjs_defaults() -> Self {
        Self {
            instruction_budget: DEFAULT_QUICKJS_BUDGET,
            max_registers: DEFAULT_QUICKJS_MAX_REGISTERS,
            max_call_depth: MAX_CALL_DEPTH,
            max_string_size: 33_554_432,
            max_heap_objects: DEFAULT_QUICKJS_MAX_HEAP_OBJECTS,
            max_total_memory_bytes: DEFAULT_QUICKJS_MAX_TOTAL_MEMORY_BYTES,
            max_console_entries: DEFAULT_QUICKJS_MAX_CONSOLE_ENTRIES,
            max_console_bytes: DEFAULT_MAX_CONSOLE_BYTES,
            max_scope_depth: DEFAULT_MAX_SCOPE_DEPTH,
            module_root: None,
            canonical_module_root: None,
            commonjs_entry: false,
            module_parser_options: ParserOptions::default(),
            module_conditions: Vec::new(),
            process_argv: Vec::new(),
            process_shape_read_allowed: false,
            disallow_dynamic_codegen: false,
            ifc_flow_policy: None,
            declassification_receipts: Vec::new(),
            granted_capabilities: BTreeSet::new(),
            extension_id: None,
            cancellation_token: None,
            checkpoint_density: 1000,
        }
    }

    /// Throughput profile defaults: generous budgets.
    pub fn v8_defaults() -> Self {
        Self {
            instruction_budget: DEFAULT_V8_BUDGET,
            max_registers: DEFAULT_V8_MAX_REGISTERS,
            max_call_depth: MAX_CALL_DEPTH,
            max_string_size: 268_435_456,
            max_heap_objects: DEFAULT_V8_MAX_HEAP_OBJECTS,
            max_total_memory_bytes: DEFAULT_V8_MAX_TOTAL_MEMORY_BYTES,
            max_console_entries: DEFAULT_V8_MAX_CONSOLE_ENTRIES,
            max_console_bytes: DEFAULT_MAX_CONSOLE_BYTES,
            max_scope_depth: DEFAULT_MAX_SCOPE_DEPTH,
            module_root: None,
            canonical_module_root: None,
            commonjs_entry: false,
            module_parser_options: ParserOptions::default(),
            module_conditions: Vec::new(),
            process_argv: Vec::new(),
            process_shape_read_allowed: false,
            disallow_dynamic_codegen: false,
            ifc_flow_policy: None,
            declassification_receipts: Vec::new(),
            granted_capabilities: BTreeSet::new(),
            extension_id: None,
            cancellation_token: None,
            checkpoint_density: 1000,
        }
    }

    /// Deterministic profile from a [`ExecutionConfig`].
    pub fn deterministic_from_config(config: &ExecutionConfig) -> Self {
        Self {
            instruction_budget: config.deterministic_budget,
            max_registers: config.deterministic_max_registers,
            max_call_depth: config.max_call_depth,
            max_string_size: 33_554_432,
            max_heap_objects: config
                .max_heap_objects
                .unwrap_or(DEFAULT_QUICKJS_MAX_HEAP_OBJECTS),
            max_total_memory_bytes: config
                .max_total_memory_bytes
                .unwrap_or(DEFAULT_QUICKJS_MAX_TOTAL_MEMORY_BYTES),
            max_console_entries: config
                .max_console_entries
                .unwrap_or(DEFAULT_QUICKJS_MAX_CONSOLE_ENTRIES),
            max_console_bytes: DEFAULT_MAX_CONSOLE_BYTES,
            max_scope_depth: DEFAULT_MAX_SCOPE_DEPTH,
            module_root: None,
            canonical_module_root: None,
            commonjs_entry: false,
            module_parser_options: ParserOptions::default(),
            module_conditions: Vec::new(),
            process_argv: Vec::new(),
            process_shape_read_allowed: false,
            disallow_dynamic_codegen: false,
            ifc_flow_policy: None,
            declassification_receipts: Vec::new(),
            granted_capabilities: BTreeSet::new(),
            extension_id: None,
            cancellation_token: None,
            checkpoint_density: 1000,
        }
    }

    /// Throughput profile from a [`ExecutionConfig`].
    pub fn throughput_from_config(config: &ExecutionConfig) -> Self {
        Self {
            instruction_budget: config.throughput_budget,
            max_registers: config.throughput_max_registers,
            max_call_depth: config.max_call_depth,
            max_string_size: 268_435_456,
            max_heap_objects: config
                .max_heap_objects
                .unwrap_or(DEFAULT_V8_MAX_HEAP_OBJECTS),
            max_total_memory_bytes: config
                .max_total_memory_bytes
                .unwrap_or(DEFAULT_V8_MAX_TOTAL_MEMORY_BYTES),
            max_console_entries: config
                .max_console_entries
                .unwrap_or(DEFAULT_V8_MAX_CONSOLE_ENTRIES),
            max_console_bytes: DEFAULT_MAX_CONSOLE_BYTES,
            max_scope_depth: DEFAULT_MAX_SCOPE_DEPTH,
            module_root: None,
            canonical_module_root: None,
            commonjs_entry: false,
            module_parser_options: ParserOptions::default(),
            module_conditions: Vec::new(),
            process_argv: Vec::new(),
            process_shape_read_allowed: false,
            disallow_dynamic_codegen: false,
            ifc_flow_policy: None,
            declassification_receipts: Vec::new(),
            granted_capabilities: BTreeSet::new(),
            extension_id: None,
            cancellation_token: None,
            checkpoint_density: 1000,
        }
    }

    /// Keep package-map condition work bounded independently of parser and
    /// instruction budgets. Two slots are reserved for `node` and load style.
    pub(crate) fn validate_module_conditions(conditions: &[String]) -> Result<(), &'static str> {
        if conditions.len() > 62 {
            return Err("module_conditions accepts at most 62 additional conditions");
        }
        if conditions.iter().any(|condition| {
            condition.is_empty() || condition.len() > 128 || condition.chars().any(char::is_control)
        }) {
            return Err(
                "module_conditions entries must contain 1 to 128 bytes with no control characters",
            );
        }
        Ok(())
    }

    /// Set the module root, canonicalizing it once for reuse during module resolution.
    pub fn set_module_root(&mut self, module_root: impl Into<String>) -> std::io::Result<()> {
        let module_root_str = module_root.into();
        let canonical = Path::new(&module_root_str).canonicalize()?;
        self.module_root = Some(module_root_str);
        self.canonical_module_root = Some(canonical);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// InterpreterEvent — structured logging
// ---------------------------------------------------------------------------

/// Structured log event from the interpreter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterpreterEvent {
    pub trace_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

// ---------------------------------------------------------------------------
// Generated-code audit surface (bd-8enww.3.4 / YTBG-C4)
// ---------------------------------------------------------------------------

/// What a [`GeneratedCodeAuditEntry`] records about `Function`-constructor code.
///
/// BotGuard-style dynamically generated code is intentionally adversarial and
/// heavy, so construction and each direct invocation of a `Function` artifact
/// are surfaced as auditable events rather than running unobserved. Nested
/// closures and continuations retain the artifact's authority/provenance but
/// do not append additional lifecycle rows; their hostcalls remain visible on
/// the ordinary decision and witness surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GeneratedCodeEventKind {
    /// `new Function(...)` produced a callable artifact (compile-time event).
    Constructed,
    /// A generated function ran to a normal completion.
    Invoked,
    /// A generated function's invocation ended in an error (thrown exception,
    /// exhausted budget, denied capability, …).
    Faulted,
}

/// One auditable event in the lifecycle of `Function`-constructor-generated
/// code (bd-8enww.3.4 / YTBG-C4). Carries the content-addressed source identity
/// plus the budget consumed by an invocation, so an operator can attribute
/// instruction spend and runtime errors back to a specific generated source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratedCodeAuditEntry {
    /// Stable synthetic source id of the generated function (`genfn:<hex>`).
    pub source_id: String,
    /// Hex SHA-256 of the full generated source text.
    pub source_hash: String,
    /// Hex SHA-256 of the parameter source.
    pub parameter_hash: String,
    /// Construction-site label (module specifier active at construction).
    pub construction_site: String,
    /// Which lifecycle event this entry records.
    pub kind: GeneratedCodeEventKind,
    /// Instructions consumed by *this* invocation (the shared interpreter
    /// budget delta across the call). `0` for a `Constructed` event.
    pub instructions_consumed: u64,
    /// JS call-stack depth of the caller at invocation entry. `0` for a
    /// `Constructed` event.
    pub caller_call_depth: usize,
    /// Effective contained capabilities granted to the generated body for this
    /// invocation, as canonical tag strings: the engine-local
    /// `vm_dispatch`/`heap_allocate` baseline plus any validated
    /// `builtin`/`console`/`timer` authority. Empty for a `Constructed` event.
    /// Dangerous capabilities are never present here — the contained-codegen
    /// envelope filters them out (see
    /// [`InterpreterCore::contained_codegen_capability_grant`]).
    pub granted_capabilities: Vec<String>,
    /// Outcome label: `"constructed"`, `"completed"`, or `"faulted:<code>"`.
    pub outcome: String,
}

// ---------------------------------------------------------------------------
// Console output capture (RC-1.10: console.log/error/warn)
// ---------------------------------------------------------------------------

/// Console log level for deterministic capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsoleLevel {
    Log,
    Error,
    Warn,
    Info,
}

/// A captured console output entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsoleEntry {
    /// Log level (log, error, warn).
    pub level: ConsoleLevel,
    /// Stringified arguments joined by space.
    pub message: String,
    /// Instruction count at which the log was emitted.
    pub instruction_index: u64,
}

/// Receives the console output a lane execution produced before it failed.
///
/// A successful run hands its console output back inside [`ExecutionResult`];
/// a failed run returns only the error, so without this sink everything the
/// program printed before throwing would be lost.
pub type FailedConsoleSink = Arc<std::sync::Mutex<Vec<ConsoleEntry>>>;

const MAX_IFC_RUNTIME_FLOW_AUDIT_ENTRIES: usize = 1024;

/// Implicit-flow program-counter taint frame pushed at a conditional branch
/// (`JumpIf` / `JumpIfNullish`) whose condition carries non-Public taint or at
/// a call site whose `callee` register carries non-Public taint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PcLabelFrame {
    /// Immediate post-dominator IP at `call_depth` where the branch's control
    /// dependence reconverges (`usize::MAX` for callee-taint frames that
    /// remain active until `call_stack.len() < call_depth`).
    pub(crate) reconvergence_ip: usize,
    /// `call_stack.len()` at which this frame was pushed.
    pub(crate) call_depth: usize,
    /// Monotonically non-decreasing joined PC taint (`top.label >= below.label`).
    pub(crate) label: Label,
}

/// Runtime sink-flow enforcement outcome recorded by [`InterpreterCore`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IfcRuntimeFlowDecision {
    /// Allowed by explicit `FlowPolicy` rule.
    AllowedPolicy,
    /// Allowed by lattice ordering (`source_label <= sink_clearance`).
    AllowedLattice,
    /// Cross-label flow authorized by a verified `DeclassificationReceipt`.
    Declassified,
    /// Refused at the sink boundary before any side effect ran.
    Denied,
}

/// Auditable runtime IFC sink check record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IfcRuntimeFlowAuditEntry {
    pub trace_id: String,
    pub instruction_ip: u32,
    pub capability: String,
    pub source_label: Label,
    pub sink_clearance: Label,
    pub decision: IfcRuntimeFlowDecision,
    pub route_id: Option<String>,
    pub receipt_id: Option<String>,
}

// ---------------------------------------------------------------------------
// ExecutionResult
// ---------------------------------------------------------------------------

/// Result of interpreter execution.
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    /// Final value (from the return register or last evaluated expression).
    pub value: Value,
    /// IFC label of the final completion value (bd-5ilh1): the provenance the
    /// top-level completion carried at its dispatch exit (direct return,
    /// finally-return, halt, or fallthrough). `Public` for engine-synthesised
    /// placeholder completions (e.g. containment-hook interruptions).
    pub completion_label: Label,
    /// Number of instructions executed.
    pub instructions_executed: u64,
    /// Number of source IR3 instructions dispatched through the compact
    /// production Tier-I representation. This is an execution fact, not an
    /// eligibility prediction: zero means the exact run stayed entirely on
    /// the canonical Tier-R handlers.
    pub tier_i_instructions_executed: u64,
    /// Tier-I instructions that additionally took a guarded borrowed/scalar
    /// specialization rather than delegating to the rich Tier-R helper path.
    pub tier_i_specialized_instructions_executed: u64,
    /// Optional containment action requested by an interpreter hook.
    pub requested_hook_action: Option<HookAction>,
    /// Witness events collected during execution.
    pub witness_events: Vec<WitnessEvent>,
    /// Hostcall decisions recorded.
    pub hostcall_decisions: Vec<HostcallDecisionRecord>,
    /// Grants of effect-free hostcalls (registry authority `Builtin` or none,
    /// plus deterministic guest microtask enqueues) that repeated their tag's
    /// last recorded grant and were counted here instead of recorded
    /// (bd-9vouw.83, bd-9vouw.76).
    pub folded_hostcall_decisions: u64,
    /// Structured events emitted.
    pub events: Vec<InterpreterEvent>,
    /// Console output captured from console.log/error/warn calls.
    pub console_output: Vec<ConsoleEntry>,
    /// Replay-visible iterator protocol traces emitted by production execution.
    pub iteration_traces: Vec<IterationTrace>,
    /// Nondeterminism trace captured during this execution, finalised and ready
    /// for deterministic replay via [`crate::deterministic_replay::ReplayEngine`].
    /// Records every nondeterministic decision (security violations, stack-limit
    /// enforcement, array-cache invalidation, property/prototype resolution) in
    /// capture order so callers can replay or cross-validate the run.
    pub nondeterminism_trace: NondeterminismTrace,
    /// Auditable lifecycle events for `Function`-constructor-generated code
    /// (bd-8enww.3.4 / YTBG-C4): one entry per construction and direct artifact
    /// invocation, carrying content-addressed source identity and the
    /// instruction budget that direct invocation consumed. Nested closure,
    /// generator, and async entries do not add rows. Empty when no dynamic code
    /// was generated.
    pub generated_code_audit: Vec<GeneratedCodeAuditEntry>,
    /// Exit status the program asked for through `process.exit(n)` or
    /// `process.exitCode = n` (bd-my9hk); `None` when it set none.
    pub exit_code: Option<i32>,
}

impl ExecutionResult {
    /// Every hostcall decision the run made: the recorded ones and the
    /// folded repeats of an effect-free grant.
    pub fn hostcall_decision_count(&self) -> u64 {
        u64::try_from(self.hostcall_decisions.len())
            .unwrap_or(u64::MAX)
            .saturating_add(self.folded_hostcall_decisions)
    }
}

/// Immutable compact dispatch plan compiled from canonical IR3.
///
/// The plan is deliberately private to the crate and non-serializable. It is
/// carried only beside the immutable IR3 inside `PreparedHybridEval`, so no
/// public caller can pair compact instructions with a different module. Each
/// cell corresponds to exactly one source IR3 instruction; unsupported cells
/// retain the baseline opcode and execute through Tier R at the same source IP.
/// Verified Tarjan SCC loop-header quantum (`[RC-E1]` / `g2vrp.15`).
/// When `max_iter_cost > 0` at `header_ip`, every path starting at `header_ip`
/// that stays within `scc_id` without re-entering `header_ip` is acyclic and
/// executes at most `max_iter_cost` Compact Tier-I instructions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CompactLoopQuantum {
    pub(crate) max_iter_cost: u16,
    pub(crate) header_scc_id: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct CompactTier1Program {
    source_module_hash: ContentHash,
    /// `Ir3FunctionDesc::canonical_value` intentionally omits rest metadata
    /// for historical hash stability. Keep an exact private ABI twin so a
    /// compact plan cannot trust frame verification from a same-hash module
    /// with different rest-parameter binding behavior.
    source_rest_param_indices: Arc<[Option<u32>]>,
    instructions: Arc<[CompactTier1Instruction]>,
    /// Per-IP Tarjan SCC membership (`0` = not in any hoisted Compact loop SCC)
    /// and loop-header AARA iteration cost quanta (`max_iter_cost > 0` on
    /// verified single-entry acyclic-body loop headers).
    loop_scc_ids: Arc<[u32]>,
    loop_quanta: Arc<[CompactLoopQuantum]>,
    compact_instruction_count: usize,
    /// Largest verified callable frame in this exact module.
    /// `None` keeps the canonical full-width reset for hand-authored or
    /// structurally unusual IR without changing module admission.
    verified_function_frame_clear_width: Option<u32>,
    /// Exact verified width for each function. The interpreter combines the
    /// selected callee width with its cross-call high-water mark, so a narrow
    /// callee cannot inherit stale registers from an earlier wider callee.
    verified_function_frame_clear_widths: Arc<[u32]>,
    /// Per-function proof that execution is a non-reentrant register-only leaf
    /// and therefore does not require a fresh lexical scope activation.
    verified_scope_inert_leaf_functions: Arc<[bool]>,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompactTier1Opcode {
    Baseline,
    LoadInt,
    LoadFloat,
    LoadBool,
    LoadNull,
    LoadUndefined,
    Move,
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Exp,
    UnaryNeg,
    UnaryPlus,
    Inc,
    Dec,
    LogicalNot,
    BitNot,
    Lt,
    Lte,
    Gt,
    Gte,
    Eq,
    StrictEq,
    NotEq,
    StrictNotEq,
    BitAnd,
    BitOr,
    BitXor,
    Shl,
    Shr,
    Ushr,
    Jump,
    JumpIf,
    JumpIfNullish,
    Halt,
}

/// Fixed-width Tier-I cell. The eight-byte scalar payload holds exact integer
/// or floating-point bits; register operands stay compact and any register that
/// does not fit `u16` is represented by a `Baseline` cell instead.
#[repr(C, align(8))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CompactTier1Instruction {
    opcode: CompactTier1Opcode,
    /// Straight-line instruction budget run starting at this IP (`[RC-E1]`
    /// AARA basic-block hoisting). `0` for `Baseline`; `1` for block-ending
    /// branches/`Halt`; `2..=255` for straight-line compact instruction runs.
    aara_block_run: u8,
    dst: u16,
    lhs: u16,
    rhs: u16,
    payload: u64,
}

impl CompactTier1Instruction {
    const BASELINE: Self = Self {
        opcode: CompactTier1Opcode::Baseline,
        aara_block_run: 0,
        dst: 0,
        lhs: 0,
        rhs: 0,
        payload: 0,
    };

    fn new(opcode: CompactTier1Opcode, dst: u16, lhs: u16, rhs: u16, payload: u64) -> Self {
        Self {
            opcode,
            aara_block_run: 0,
            dst,
            lhs,
            rhs,
            payload,
        }
    }

    fn with_dst(opcode: CompactTier1Opcode, dst: u32, payload: u64) -> Option<Self> {
        Some(Self::new(opcode, u16::try_from(dst).ok()?, 0, 0, payload))
    }

    fn with_unary(opcode: CompactTier1Opcode, dst: u32, src: u32) -> Option<Self> {
        Some(Self::new(
            opcode,
            u16::try_from(dst).ok()?,
            u16::try_from(src).ok()?,
            0,
            0,
        ))
    }

    fn with_binary(opcode: CompactTier1Opcode, dst: u32, lhs: u32, rhs: u32) -> Option<Self> {
        Some(Self::new(
            opcode,
            u16::try_from(dst).ok()?,
            u16::try_from(lhs).ok()?,
            u16::try_from(rhs).ok()?,
            0,
        ))
    }
}

impl CompactTier1Program {
    /// Compile a source-IP-preserving compact plan. Unsupported instructions
    /// remain explicit baseline cells; compilation itself never changes module
    /// admission or execution semantics.
    pub(crate) fn compile(module: &Ir3Module) -> Option<Self> {
        Self::compile_with_known_hash(module, None)
    }

    /// [`Self::compile`] given `module`'s content hash when the caller already
    /// computed it for the same module (the orchestrator's routing context),
    /// instead of a further full canonical encoding (bd-9vouw.382).
    /// [`Self::validate_module`] still rehashes the module it is given.
    pub(crate) fn compile_with_source_hash(
        module: &Ir3Module,
        source_hash: ContentHash,
    ) -> Option<Self> {
        Self::compile_with_known_hash(module, Some(source_hash))
    }

    fn compile_with_known_hash(
        module: &Ir3Module,
        source_hash: Option<ContentHash>,
    ) -> Option<Self> {
        let verified_function_frame_clear_width = Self::verified_function_frame_clear_width(module);
        let verified_function_frame_clear_widths = if verified_function_frame_clear_width.is_some()
        {
            module
                .function_table
                .iter()
                .map(|function| function.frame_size)
                .collect::<Arc<[u32]>>()
        } else {
            Arc::from([])
        };
        let verified_scope_inert_leaf_functions =
            if verified_function_frame_clear_width.is_some() {
                Self::verified_scope_inert_leaf_functions(module)
            } else {
                vec![false; module.function_table.len()]
            }
            .into();
        let mut compact_instruction_count = 0usize;
        let mut compact_work_instruction_count = 0usize;
        let mut cells = module
            .instructions
            .iter()
            .map(|instruction| {
                let compact = Self::compile_instruction(instruction)
                    .unwrap_or(CompactTier1Instruction::BASELINE);
                if compact.opcode != CompactTier1Opcode::Baseline {
                    compact_instruction_count = compact_instruction_count.saturating_add(1);
                    if compact.opcode != CompactTier1Opcode::Halt {
                        compact_work_instruction_count =
                            compact_work_instruction_count.saturating_add(1);
                    }
                }
                compact
            })
            .collect::<Vec<_>>();
        if compact_work_instruction_count == 0 {
            return None;
        }
        for idx in (0..cells.len()).rev() {
            let run = match cells[idx].opcode {
                CompactTier1Opcode::Baseline => 0,
                CompactTier1Opcode::Jump
                | CompactTier1Opcode::JumpIf
                | CompactTier1Opcode::JumpIfNullish
                | CompactTier1Opcode::Halt => 1,
                _ => cells
                    .get(idx + 1)
                    .map_or(0, |next| next.aara_block_run)
                    .saturating_add(1),
            };
            cells[idx].aara_block_run = run;
        }
        let (loop_scc_ids, loop_quanta) = Self::compute_tarjan_loop_quanta(&cells);
        let instructions: Arc<[CompactTier1Instruction]> = cells.into();
        let source_module_hash = source_hash.unwrap_or_else(|| module.content_hash());
        debug_assert_eq!(source_module_hash, module.content_hash());
        Some(Self {
            source_module_hash,
            source_rest_param_indices: module
                .function_table
                .iter()
                .map(|function| function.rest_param_index)
                .collect::<Arc<[_]>>(),
            instructions,
            loop_scc_ids,
            loop_quanta,
            compact_instruction_count,
            verified_function_frame_clear_width,
            verified_function_frame_clear_widths,
            verified_scope_inert_leaf_functions,
        })
    }

    /// Iterative Tarjan SCC + Kahn acyclic longest-path AARA bound pass
    /// (`[RC-E1]` / `g2vrp.15`). Decomposes nested loops until innermost
    /// single-entry Compact-only loop SCCs are isolated and statically bounded.
    fn compute_tarjan_loop_quanta(
        cells: &[CompactTier1Instruction],
    ) -> (Arc<[u32]>, Arc<[CompactLoopQuantum]>) {
        let n = cells.len();
        let mut scc_ids = vec![0u32; n];
        let mut quanta = vec![
            CompactLoopQuantum {
                max_iter_cost: 0,
                header_scc_id: 0,
            };
            n
        ];
        if n == 0 {
            return (scc_ids.into(), quanta.into());
        }

        let mut succs: Vec<[Option<usize>; 2]> = vec![[None, None]; n];
        let mut preds: Vec<Vec<usize>> = vec![Vec::new(); n];
        for (u, cell) in cells.iter().enumerate() {
            let edges = match cell.opcode {
                CompactTier1Opcode::Baseline | CompactTier1Opcode::Halt => [None, None],
                CompactTier1Opcode::Jump => {
                    let t = usize::try_from(cell.payload).ok().filter(|&t| t < n);
                    [t, None]
                }
                CompactTier1Opcode::JumpIf | CompactTier1Opcode::JumpIfNullish => {
                    let t = usize::try_from(cell.payload).ok().filter(|&t| t < n);
                    let f = u.checked_add(1).filter(|&f| f < n);
                    if t == f { [t, None] } else { [t, f] }
                }
                _ => [u.checked_add(1).filter(|&f| f < n), None],
            };
            succs[u] = edges;
            for v in edges.into_iter().flatten() {
                preds[v].push(u);
            }
        }

        let mut in_subset = vec![false; n];
        let mut index_of = vec![0u32; n];
        let mut lowlink = vec![0u32; n];
        let mut on_stack = vec![false; n];
        let mut tarjan_stack: Vec<usize> = Vec::new();
        let mut dfs_frames: Vec<(usize, u8)> = Vec::new();
        let mut next_scc_tag = 1u32;

        let mut worklist: Vec<Vec<usize>> = vec![(0..n).collect()];
        while let Some(subset) = worklist.pop() {
            if subset.is_empty() {
                continue;
            }
            for &v in &subset {
                in_subset[v] = true;
                index_of[v] = 0;
                lowlink[v] = 0;
                on_stack[v] = false;
            }
            let mut next_index = 1u32;
            let mut found_sccs: Vec<Vec<usize>> = Vec::new();

            for &start in &subset {
                if index_of[start] != 0 {
                    continue;
                }
                index_of[start] = next_index;
                lowlink[start] = next_index;
                next_index = next_index.saturating_add(1);
                tarjan_stack.push(start);
                on_stack[start] = true;
                dfs_frames.push((start, 0));

                while let Some((u, edge_slot)) = dfs_frames.pop() {
                    if edge_slot < 2 {
                        dfs_frames.push((u, edge_slot + 1));
                        if let Some(w) = succs[u][usize::from(edge_slot)]
                            && in_subset[w]
                        {
                            if index_of[w] == 0 {
                                index_of[w] = next_index;
                                lowlink[w] = next_index;
                                next_index = next_index.saturating_add(1);
                                tarjan_stack.push(w);
                                on_stack[w] = true;
                                dfs_frames.push((w, 0));
                            } else if on_stack[w] {
                                lowlink[u] = lowlink[u].min(index_of[w]);
                            }
                        }
                    } else {
                        for w in succs[u].into_iter().flatten() {
                            if in_subset[w] && index_of[w] > index_of[u] && on_stack[w] {
                                lowlink[u] = lowlink[u].min(lowlink[w]);
                            }
                        }
                        if lowlink[u] == index_of[u] {
                            let mut comp = Vec::new();
                            while let Some(w) = tarjan_stack.pop() {
                                on_stack[w] = false;
                                comp.push(w);
                                if w == u {
                                    break;
                                }
                            }
                            found_sccs.push(comp);
                        }
                    }
                }
            }

            for &v in &subset {
                in_subset[v] = false;
            }

            for mut comp in found_sccs {
                comp.sort_unstable();
                let is_loop = comp.len() >= 2 || {
                    let only = comp[0];
                    succs[only].into_iter().flatten().any(|w| w == only)
                };
                if !is_loop {
                    continue;
                }
                if comp.iter().any(|&v| {
                    matches!(
                        cells[v].opcode,
                        CompactTier1Opcode::Baseline | CompactTier1Opcode::Halt
                    )
                }) {
                    // Non-compact op inside outer SCC: strip min vertex to still
                    // expose any pure-Compact inner loop SCCs.
                    if comp.len() > 1 {
                        comp.remove(0);
                        worklist.push(comp);
                    }
                    continue;
                }

                for &v in &comp {
                    in_subset[v] = true;
                }
                let mut entries = Vec::new();
                for &v in &comp {
                    let is_entry = v == 0 || preds[v].iter().any(|&p| !in_subset[p]);
                    if is_entry {
                        entries.push(v);
                    }
                }
                if entries.len() > 1 {
                    for &v in &comp {
                        in_subset[v] = false;
                    }
                    continue;
                }
                let header = entries.first().copied().unwrap_or(comp[0]);

                // Build loop-body DAG by cutting backedges `* -> header`.
                let mut indegree = vec![0u32; comp.len()];
                for (idx_v, &v) in comp.iter().enumerate() {
                    if v == header {
                        continue;
                    }
                    for &p in &preds[v] {
                        if in_subset[p] {
                            indegree[idx_v] = indegree[idx_v].saturating_add(1);
                        }
                    }
                }
                let header_pos = comp.binary_search(&header).expect("header in sorted comp");
                let mut queue = std::collections::VecDeque::new();
                let mut dist = vec![0u32; comp.len()];
                for (i, &deg) in indegree.iter().enumerate() {
                    if deg == 0 {
                        queue.push_back(i);
                    }
                }
                dist[header_pos] = 1;
                let mut visited = 0usize;
                let mut max_steps = 1u32;
                while let Some(u_pos) = queue.pop_front() {
                    visited += 1;
                    let u = comp[u_pos];
                    let du = dist[u_pos];
                    if du > max_steps {
                        max_steps = du;
                    }
                    for w in succs[u].into_iter().flatten() {
                        if !in_subset[w] || w == header {
                            continue;
                        }
                        let w_pos = comp.binary_search(&w).expect("member in sorted comp");
                        if du > 0 {
                            dist[w_pos] = dist[w_pos].max(du.saturating_add(1));
                        }
                        indegree[w_pos] = indegree[w_pos].saturating_sub(1);
                        if indegree[w_pos] == 0 {
                            queue.push_back(w_pos);
                        }
                    }
                }
                for &v in &comp {
                    in_subset[v] = false;
                }

                if visited < comp.len() {
                    // Nested inner loop exists inside `comp \ {header}`: decompose
                    // recursively so the innermost hot loop gets hoisted!
                    let residual: Vec<usize> = comp.into_iter().filter(|&v| v != header).collect();
                    if !residual.is_empty() {
                        worklist.push(residual);
                    }
                    continue;
                }

                if let Ok(cost_u16) = u16::try_from(max_steps)
                    && cost_u16 >= 1
                    && next_scc_tag < u32::MAX
                {
                    let tag = next_scc_tag;
                    next_scc_tag += 1;
                    for &v in &comp {
                        scc_ids[v] = tag;
                    }
                    quanta[header] = CompactLoopQuantum {
                        max_iter_cost: cost_u16,
                        header_scc_id: tag,
                    };
                }
            }
        }

        (scc_ids.into(), quanta.into())
    }

    fn verified_scope_inert_leaf_functions(module: &Ir3Module) -> Vec<bool> {
        let instruction_count = module.instructions.len();
        module
            .function_table
            .iter()
            .enumerate()
            .map(|(function_index, function)| {
                if function_index == 0 || function.is_generator {
                    return false;
                }
                let start = function.entry as usize;
                let end = module
                    .function_table
                    .get(function_index + 1)
                    .map_or(instruction_count, |next| next.entry as usize);
                module
                    .instructions
                    .get(start..end)
                    .is_some_and(|window| window.iter().all(Self::instruction_is_scope_inert_leaf))
            })
            .collect()
    }

    fn instruction_is_scope_inert_leaf(instruction: &Ir3Instruction) -> bool {
        matches!(
            instruction,
            Ir3Instruction::LoadInt { .. }
                | Ir3Instruction::LoadFloat { .. }
                | Ir3Instruction::LoadBool { .. }
                | Ir3Instruction::LoadNull { .. }
                | Ir3Instruction::LoadUndefined { .. }
                | Ir3Instruction::Move { .. }
                | Ir3Instruction::Add { .. }
                | Ir3Instruction::Sub { .. }
                | Ir3Instruction::Mul { .. }
                | Ir3Instruction::Div { .. }
                | Ir3Instruction::Mod { .. }
                | Ir3Instruction::Exp { .. }
                | Ir3Instruction::UnaryNeg { .. }
                | Ir3Instruction::UnaryPlus { .. }
                | Ir3Instruction::Inc { .. }
                | Ir3Instruction::Dec { .. }
                | Ir3Instruction::LogicalNot { .. }
                | Ir3Instruction::BitNot { .. }
                | Ir3Instruction::Lt { .. }
                | Ir3Instruction::Lte { .. }
                | Ir3Instruction::Gt { .. }
                | Ir3Instruction::Gte { .. }
                | Ir3Instruction::Eq { .. }
                | Ir3Instruction::StrictEq { .. }
                | Ir3Instruction::NotEq { .. }
                | Ir3Instruction::StrictNotEq { .. }
                | Ir3Instruction::BitAnd { .. }
                | Ir3Instruction::BitOr { .. }
                | Ir3Instruction::BitXor { .. }
                | Ir3Instruction::Shl { .. }
                | Ir3Instruction::Shr { .. }
                | Ir3Instruction::Ushr { .. }
                | Ir3Instruction::Jump { .. }
                | Ir3Instruction::JumpIf { .. }
                | Ir3Instruction::JumpIfNullish { .. }
                | Ir3Instruction::Return { .. }
        )
    }

    /// Validate every function window before trusting descriptor frame widths.
    ///
    /// The returned module-wide maximum is the admission proof for the exact
    /// per-function widths stored beside the compact program. Runtime entry
    /// combines the selected callee width with a monotonic cross-call
    /// high-water mark, so alternating wide and narrow calls cannot retain a
    /// prior value or IFC label. Any malformed descriptor, register span,
    /// fallthrough edge, or cross-function control target disables the
    /// optimization and preserves the legacy full-width reset.
    /// Every function's `frame_size`, when the whole module verifies against
    /// it (`verified_function_frame_clear_width`).
    fn verified_frame_widths(module: &Ir3Module) -> Option<Arc<[u32]>> {
        Self::verified_function_frame_clear_width(module)?;
        Some(
            module
                .function_table
                .iter()
                .map(|function| function.frame_size)
                .collect(),
        )
    }

    fn verified_function_frame_clear_width(module: &Ir3Module) -> Option<u32> {
        let instruction_count = u32::try_from(module.instructions.len()).ok()?;
        let main = module.function_table.first()?;
        if main.entry != 0 {
            return None;
        }

        let mut widest_function = 0u32;
        for (function_index, function) in module.function_table.iter().enumerate() {
            let start = function.entry;
            let end = module
                .function_table
                .get(function_index + 1)
                .map_or(instruction_count, |next| next.entry);
            if start >= end || end > instruction_count || function.frame_size == 0 {
                return None;
            }
            if function.arity > function.frame_size
                || function
                    .rest_param_index
                    .is_some_and(|rest| rest >= function.arity)
            {
                return None;
            }

            let window = module.instructions.get(start as usize..end as usize)?;
            for instruction in window {
                if Self::instruction_register_requirement(instruction)? > function.frame_size
                    || !Self::instruction_targets_stay_in_window(instruction, start, end)
                {
                    return None;
                }
            }

            // Falling off the final instruction stream is already a defined
            // implicit return. Falling into the next physical function body
            // is not frame-safe, so intermediate windows must end in an
            // instruction that cannot advance to `end`.
            if function_index + 1 < module.function_table.len()
                && !window
                    .last()
                    .is_some_and(Self::instruction_prevents_fallthrough)
            {
                return None;
            }

            widest_function = widest_function.max(function.frame_size);
        }
        Some(widest_function)
    }

    fn instruction_register_requirement(instruction: &Ir3Instruction) -> Option<u32> {
        fn requirement(registers: &[u32], ranges: &[RegRange]) -> Option<u32> {
            let mut required = 0u32;
            for register in registers {
                required = required.max(register.checked_add(1)?);
            }
            for range in ranges {
                if range.count > 0 {
                    required = required.max(range.start.checked_add(range.count)?);
                }
            }
            Some(required)
        }

        match instruction {
            Ir3Instruction::LoadInt { dst, .. }
            | Ir3Instruction::LoadBigInt { dst, .. }
            | Ir3Instruction::LoadFloat { dst, .. }
            | Ir3Instruction::LoadStr { dst, .. }
            | Ir3Instruction::LoadBool { dst, .. }
            | Ir3Instruction::LoadNull { dst }
            | Ir3Instruction::LoadUndefined { dst }
            | Ir3Instruction::NewObject { dst }
            | Ir3Instruction::NewArray { dst }
            | Ir3Instruction::LoadThis { dst }
            | Ir3Instruction::LoadNewTarget { dst }
            | Ir3Instruction::LoadSuper { dst }
            | Ir3Instruction::EnterCatch { dst }
            | Ir3Instruction::LoadScoped { dst, .. }
            | Ir3Instruction::LoadName { dst, .. }
            | Ir3Instruction::ResolveNameStatus { dst, .. }
            | Ir3Instruction::DeleteName { dst, .. }
            | Ir3Instruction::CreateClosure { dst, .. }
            | Ir3Instruction::CreateArrowClosure { dst, .. }
            | Ir3Instruction::CreateGenerator { dst, .. }
            | Ir3Instruction::CreateAsyncFunction { dst, .. }
            | Ir3Instruction::CreateAsyncArrowClosure { dst, .. }
            | Ir3Instruction::CreateAsyncGenerator { dst, .. } => requirement(&[*dst], &[]),
            Ir3Instruction::UnaryNeg { dst, src }
            | Ir3Instruction::UnaryPlus { dst, src }
            | Ir3Instruction::Inc { dst, src }
            | Ir3Instruction::Dec { dst, src }
            | Ir3Instruction::LogicalNot { dst, src }
            | Ir3Instruction::BitNot { dst, src }
            | Ir3Instruction::TypeOf { dst, src }
            | Ir3Instruction::Void { dst, src }
            | Ir3Instruction::Move { dst, src }
            | Ir3Instruction::ForInInit { src, dst }
            | Ir3Instruction::ForOfInit { src, dst } => requirement(&[*dst, *src], &[]),
            Ir3Instruction::Add { dst, lhs, rhs }
            | Ir3Instruction::Sub { dst, lhs, rhs }
            | Ir3Instruction::Mul { dst, lhs, rhs }
            | Ir3Instruction::Div { dst, lhs, rhs }
            | Ir3Instruction::Mod { dst, lhs, rhs }
            | Ir3Instruction::Exp { dst, lhs, rhs }
            | Ir3Instruction::Lt { dst, lhs, rhs }
            | Ir3Instruction::Lte { dst, lhs, rhs }
            | Ir3Instruction::Gt { dst, lhs, rhs }
            | Ir3Instruction::Gte { dst, lhs, rhs }
            | Ir3Instruction::Eq { dst, lhs, rhs }
            | Ir3Instruction::StrictEq { dst, lhs, rhs }
            | Ir3Instruction::NotEq { dst, lhs, rhs }
            | Ir3Instruction::StrictNotEq { dst, lhs, rhs }
            | Ir3Instruction::BitAnd { dst, lhs, rhs }
            | Ir3Instruction::BitOr { dst, lhs, rhs }
            | Ir3Instruction::BitXor { dst, lhs, rhs }
            | Ir3Instruction::Shl { dst, lhs, rhs }
            | Ir3Instruction::Shr { dst, lhs, rhs }
            | Ir3Instruction::Ushr { dst, lhs, rhs }
            | Ir3Instruction::InstanceOf { dst, lhs, rhs }
            | Ir3Instruction::InOp { dst, lhs, rhs } => requirement(&[*dst, *lhs, *rhs], &[]),
            Ir3Instruction::Construct { callee, args, dst }
            | Ir3Instruction::Call { callee, args, dst } => requirement(&[*callee, *dst], &[*args]),
            Ir3Instruction::ConstructWithNewTarget {
                callee,
                new_target,
                args,
                dst,
            } => requirement(&[*callee, *new_target, *dst], &[*args]),
            Ir3Instruction::ConstructSuper { args, dst }
            | Ir3Instruction::HostCall { args, dst, .. }
            | Ir3Instruction::TemplateLiteral { parts: args, dst } => {
                requirement(&[*dst], &[*args])
            }
            Ir3Instruction::RegisterDerivedConstructor {
                constructor,
                parent,
                ..
            } => requirement(&[*constructor, *parent], &[]),
            Ir3Instruction::ForInNext {
                iterator,
                value_dst,
                ..
            }
            | Ir3Instruction::ForOfNext {
                iterator,
                value_dst,
                ..
            } => requirement(&[*iterator, *value_dst], &[]),
            Ir3Instruction::IteratorClose { iterator, .. }
            | Ir3Instruction::Return { value: iterator }
            | Ir3Instruction::Throw { value: iterator }
            | Ir3Instruction::StoreScoped { src: iterator, .. }
            | Ir3Instruction::PutName { src: iterator, .. }
            | Ir3Instruction::InitBinding { src: iterator, .. }
            | Ir3Instruction::ExportBinding { src: iterator, .. }
            | Ir3Instruction::AwaitValue {
                promise_reg: iterator,
            }
            | Ir3Instruction::AsyncReturn {
                value_reg: iterator,
            }
            | Ir3Instruction::AsyncThrow {
                error_reg: iterator,
            }
            | Ir3Instruction::ModuleAwaitValue {
                promise_reg: iterator,
            } => requirement(&[*iterator], &[]),
            Ir3Instruction::JumpIf { cond, .. } | Ir3Instruction::JumpIfNullish { cond, .. } => {
                requirement(&[*cond], &[])
            }
            Ir3Instruction::CallMethod {
                receiver,
                callee,
                args,
                dst,
            } => requirement(&[*receiver, *callee, *dst], &[*args]),
            Ir3Instruction::GetProperty { obj, key, dst }
            | Ir3Instruction::DeleteProperty { obj, key, dst } => {
                requirement(&[*obj, *key, *dst], &[])
            }
            Ir3Instruction::SetProperty { obj, key, val }
            | Ir3Instruction::SetPropertySloppy { obj, key, val }
            | Ir3Instruction::CreateDataProperty { obj, key, val } => {
                requirement(&[*obj, *key, *val], &[])
            }
            Ir3Instruction::DefineAccessor { obj, key, func, .. }
            | Ir3Instruction::DefineMethod { obj, key, func } => {
                requirement(&[*obj, *key, *func], &[])
            }
            Ir3Instruction::ArrayPush { array, element }
            | Ir3Instruction::SpreadIntoArray {
                array,
                iterable: element,
            }
            | Ir3Instruction::SpreadIntoObject {
                target: array,
                source: element,
            } => requirement(&[*array, *element], &[]),
            Ir3Instruction::ArraySlice { array, start, dst } => {
                requirement(&[*array, *start, *dst], &[])
            }
            Ir3Instruction::PutNameWithStatus { src, status, .. } => {
                requirement(&[*src, *status], &[])
            }
            Ir3Instruction::ImportModule { specifier, dst, .. } => {
                requirement(&[*specifier, *dst], &[])
            }
            Ir3Instruction::Yield {
                value, resume_dst, ..
            } => requirement(&[*value, *resume_dst], &[]),
            Ir3Instruction::Jump { .. }
            | Ir3Instruction::Halt
            | Ir3Instruction::BeginTry { .. }
            | Ir3Instruction::EndTry
            | Ir3Instruction::EnterFinally
            | Ir3Instruction::EndFinally
            | Ir3Instruction::DiscardAbruptCompletion
            | Ir3Instruction::PushCapture { .. }
            | Ir3Instruction::PushScope
            | Ir3Instruction::PopScope
            | Ir3Instruction::DeclareBinding { .. }
            | Ir3Instruction::CreatePerIterationBinding { .. } => requirement(&[], &[]),
        }
    }

    fn instruction_targets_stay_in_window(
        instruction: &Ir3Instruction,
        start: u32,
        end: u32,
    ) -> bool {
        let in_window = |target: u32| (start..end).contains(&target);
        match instruction {
            Ir3Instruction::Jump { target }
            | Ir3Instruction::JumpIf { target, .. }
            | Ir3Instruction::JumpIfNullish { target, .. }
            | Ir3Instruction::ForInNext {
                done_target: target,
                ..
            }
            | Ir3Instruction::ForOfNext {
                done_target: target,
                ..
            } => in_window(*target),
            Ir3Instruction::BeginTry {
                catch_target,
                finally_target,
            } => in_window(*catch_target) && finally_target.is_none_or(in_window),
            _ => true,
        }
    }

    fn instruction_prevents_fallthrough(instruction: &Ir3Instruction) -> bool {
        matches!(
            instruction,
            Ir3Instruction::Jump { .. }
                | Ir3Instruction::Return { .. }
                | Ir3Instruction::Throw { .. }
                | Ir3Instruction::AsyncReturn { .. }
                | Ir3Instruction::AsyncThrow { .. }
                | Ir3Instruction::Halt
        )
    }

    fn function_frame_clear_width(&self, max_registers: u32) -> Option<usize> {
        self.verified_function_frame_clear_width
            .filter(|width| *width > 0 && *width <= max_registers)
            .map(|width| width as usize)
    }

    fn callee_frame_clear_width(&self, function_index: u32, max_registers: u32) -> Option<usize> {
        self.verified_function_frame_clear_widths
            .get(function_index as usize)
            .copied()
            .filter(|width| *width > 0 && *width <= max_registers)
            .map(|width| width as usize)
    }

    fn scope_inert_leaf_function(&self, function_index: u32) -> bool {
        self.verified_scope_inert_leaf_functions
            .get(function_index as usize)
            .copied()
            .unwrap_or(false)
    }

    fn compile_instruction(instruction: &Ir3Instruction) -> Option<CompactTier1Instruction> {
        use CompactTier1Opcode as Op;
        match instruction {
            Ir3Instruction::LoadInt { dst, value } => {
                CompactTier1Instruction::with_dst(Op::LoadInt, *dst, *value as u64)
            }
            Ir3Instruction::LoadFloat { dst, bits } => {
                CompactTier1Instruction::with_dst(Op::LoadFloat, *dst, *bits)
            }
            Ir3Instruction::LoadBool { dst, value } => {
                CompactTier1Instruction::with_dst(Op::LoadBool, *dst, u64::from(*value))
            }
            Ir3Instruction::LoadNull { dst } => {
                CompactTier1Instruction::with_dst(Op::LoadNull, *dst, 0)
            }
            Ir3Instruction::LoadUndefined { dst } => {
                CompactTier1Instruction::with_dst(Op::LoadUndefined, *dst, 0)
            }
            Ir3Instruction::Move { dst, src } => {
                CompactTier1Instruction::with_unary(Op::Move, *dst, *src)
            }
            Ir3Instruction::Add { dst, lhs, rhs } => {
                CompactTier1Instruction::with_binary(Op::Add, *dst, *lhs, *rhs)
            }
            Ir3Instruction::Sub { dst, lhs, rhs } => {
                CompactTier1Instruction::with_binary(Op::Sub, *dst, *lhs, *rhs)
            }
            Ir3Instruction::Mul { dst, lhs, rhs } => {
                CompactTier1Instruction::with_binary(Op::Mul, *dst, *lhs, *rhs)
            }
            Ir3Instruction::Div { dst, lhs, rhs } => {
                CompactTier1Instruction::with_binary(Op::Div, *dst, *lhs, *rhs)
            }
            Ir3Instruction::Mod { dst, lhs, rhs } => {
                CompactTier1Instruction::with_binary(Op::Mod, *dst, *lhs, *rhs)
            }
            Ir3Instruction::Exp { dst, lhs, rhs } => {
                CompactTier1Instruction::with_binary(Op::Exp, *dst, *lhs, *rhs)
            }
            Ir3Instruction::UnaryNeg { dst, src } => {
                CompactTier1Instruction::with_unary(Op::UnaryNeg, *dst, *src)
            }
            Ir3Instruction::UnaryPlus { dst, src } => {
                CompactTier1Instruction::with_unary(Op::UnaryPlus, *dst, *src)
            }
            Ir3Instruction::Inc { dst, src } => {
                CompactTier1Instruction::with_unary(Op::Inc, *dst, *src)
            }
            Ir3Instruction::Dec { dst, src } => {
                CompactTier1Instruction::with_unary(Op::Dec, *dst, *src)
            }
            Ir3Instruction::LogicalNot { dst, src } => {
                CompactTier1Instruction::with_unary(Op::LogicalNot, *dst, *src)
            }
            Ir3Instruction::BitNot { dst, src } => {
                CompactTier1Instruction::with_unary(Op::BitNot, *dst, *src)
            }
            Ir3Instruction::Lt { dst, lhs, rhs } => {
                CompactTier1Instruction::with_binary(Op::Lt, *dst, *lhs, *rhs)
            }
            Ir3Instruction::Lte { dst, lhs, rhs } => {
                CompactTier1Instruction::with_binary(Op::Lte, *dst, *lhs, *rhs)
            }
            Ir3Instruction::Gt { dst, lhs, rhs } => {
                CompactTier1Instruction::with_binary(Op::Gt, *dst, *lhs, *rhs)
            }
            Ir3Instruction::Gte { dst, lhs, rhs } => {
                CompactTier1Instruction::with_binary(Op::Gte, *dst, *lhs, *rhs)
            }
            Ir3Instruction::Eq { dst, lhs, rhs } => {
                CompactTier1Instruction::with_binary(Op::Eq, *dst, *lhs, *rhs)
            }
            Ir3Instruction::StrictEq { dst, lhs, rhs } => {
                CompactTier1Instruction::with_binary(Op::StrictEq, *dst, *lhs, *rhs)
            }
            Ir3Instruction::NotEq { dst, lhs, rhs } => {
                CompactTier1Instruction::with_binary(Op::NotEq, *dst, *lhs, *rhs)
            }
            Ir3Instruction::StrictNotEq { dst, lhs, rhs } => {
                CompactTier1Instruction::with_binary(Op::StrictNotEq, *dst, *lhs, *rhs)
            }
            Ir3Instruction::BitAnd { dst, lhs, rhs } => {
                CompactTier1Instruction::with_binary(Op::BitAnd, *dst, *lhs, *rhs)
            }
            Ir3Instruction::BitOr { dst, lhs, rhs } => {
                CompactTier1Instruction::with_binary(Op::BitOr, *dst, *lhs, *rhs)
            }
            Ir3Instruction::BitXor { dst, lhs, rhs } => {
                CompactTier1Instruction::with_binary(Op::BitXor, *dst, *lhs, *rhs)
            }
            Ir3Instruction::Shl { dst, lhs, rhs } => {
                CompactTier1Instruction::with_binary(Op::Shl, *dst, *lhs, *rhs)
            }
            Ir3Instruction::Shr { dst, lhs, rhs } => {
                CompactTier1Instruction::with_binary(Op::Shr, *dst, *lhs, *rhs)
            }
            Ir3Instruction::Ushr { dst, lhs, rhs } => {
                CompactTier1Instruction::with_binary(Op::Ushr, *dst, *lhs, *rhs)
            }
            Ir3Instruction::Jump { target } => Some(CompactTier1Instruction::new(
                Op::Jump,
                0,
                0,
                0,
                u64::from(*target),
            )),
            Ir3Instruction::JumpIf { cond, target } => Some(CompactTier1Instruction::new(
                Op::JumpIf,
                0,
                u16::try_from(*cond).ok()?,
                0,
                u64::from(*target),
            )),
            Ir3Instruction::JumpIfNullish { cond, target } => Some(CompactTier1Instruction::new(
                Op::JumpIfNullish,
                0,
                u16::try_from(*cond).ok()?,
                0,
                u64::from(*target),
            )),
            Ir3Instruction::Halt => Some(CompactTier1Instruction::new(Op::Halt, 0, 0, 0, 0)),
            _ => None,
        }
    }

    fn validate_module(&self, module: &Ir3Module) -> Result<(), InterpreterError> {
        let actual_hash = module.content_hash();
        if self.source_module_hash != actual_hash {
            return Err(InterpreterError::InternalError {
                details: format!(
                    "compact Tier-I plan/module identity mismatch: expected {}, got {}",
                    self.source_module_hash, actual_hash
                ),
            });
        }
        if self.source_rest_param_indices.len() != module.function_table.len()
            || self
                .source_rest_param_indices
                .iter()
                .zip(&module.function_table)
                .any(|(expected, actual)| *expected != actual.rest_param_index)
        {
            return Err(InterpreterError::InternalError {
                details: "compact Tier-I plan/module rest-parameter ABI mismatch".to_string(),
            });
        }
        Ok(())
    }

    fn instruction_at(&self, ip: usize) -> Option<CompactTier1Instruction> {
        self.instructions
            .get(ip)
            .copied()
            .filter(|instruction| instruction.opcode != CompactTier1Opcode::Baseline)
    }

    #[inline(always)]
    fn block_slice_at(&self, ip: usize) -> Option<&[CompactTier1Instruction]> {
        let first = self.instructions.get(ip)?;
        let run = usize::from(first.aara_block_run);
        if run < 2 {
            return None;
        }
        self.instructions.get(ip..ip.checked_add(run)?)
    }

    #[inline(always)]
    fn loop_quantum_at(&self, ip: usize) -> Option<CompactLoopQuantum> {
        self.loop_quanta
            .get(ip)
            .copied()
            .filter(|q| q.max_iter_cost >= 1)
    }

    #[inline(always)]
    fn ip_in_loop_scc(&self, header_scc_id: u32, ip: usize) -> bool {
        self.loop_scc_ids.get(ip).copied() == Some(header_scc_id)
    }

    #[inline(always)]
    fn raw_cell_at(&self, ip: usize) -> Option<CompactTier1Instruction> {
        self.instructions.get(ip).copied()
    }

    pub(crate) fn compact_instruction_count(&self) -> usize {
        self.compact_instruction_count
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TraceHandoff {
    /// Preserve the public post-execution `InterpreterCore` trace view.
    RetainInCore,
    /// Move the trace out of a private one-shot lane core that is about to be
    /// dropped, avoiding a deep clone of every event payload and component.
    DrainEphemeralCore,
}

// ExecutionSeed moved to line 2266 as an enum for lazy materialization (PERF-H2.2)

#[derive(Debug, Clone)]
struct ModuleExecutionSnapshot {
    accounted_bytes: u64,
    registers: Vec<Value>,
    /// [`InterpreterCore::registers_memory_bytes`] of `registers`, which no
    /// one writes while they are parked here.
    register_bytes: u64,
    generator_delegation: Option<GeneratorDelegation>,
    /// IFC labels parallel the logical register file. Inline callback
    /// execution replaces the register values, so its snapshot must preserve
    /// labels as well or a stream/event callback can corrupt caller taint.
    register_labels: Vec<Label>,
    /// [`InterpreterCore::register_labels_memory_bytes`] of
    /// `register_labels`, which no one writes while they are parked here.
    register_label_bytes: u64,
    /// [`InterpreterCore::register_dirty_end`] of these files, which
    /// `restore_module_execution` restores: the whole file's length would make
    /// the next call after every isolated call clear to its end
    /// (bd-9vouw.499).
    register_dirty_end: usize,
    /// PC-style provenance for an isolated stream/event callback. Keeping one
    /// snapshotted label avoids cloning a Custom label into every register.
    active_inline_callback_context_label: Option<Label>,
    /// Post-dominator implicit-flow PC-label frames owned by the suspended
    /// activation.
    pc_label_stack: Vec<PcLabelFrame>,
    call_stack: Vec<CallFrame>,
    ip: usize,
    register_base: usize,
    register_width: usize,
    catch_frames: Vec<CatchFrame>,
    pending_exception: Option<Value>,
    pending_exception_label: Label,
    pending_hostcall_result_label: Option<Label>,
    pending_return: Option<LabeledReturn>,
    suspended_abrupt_completions: Vec<AbruptCompletion>,
    finally_frames: Vec<FinallyFrame>,
    pending_finally_entry: Option<PendingFinallyEntry>,
    scope_chain: ScopeChain,
    pending_captures: Vec<u32>,
    current_module_specifier: Option<String>,
    active_generated_function_artifact: Option<GeneratedFunctionArtifactHandle>,
}

/// IFC labels carried alongside values entering an isolated interpreter
/// wrapper. `Uniform` is used when an array-like argument carrier has one
/// aggregate label but no per-property label sidecar; it avoids allocating an
/// attacker-sized `Vec<Label>` before the wrapper's memory preflight.
#[derive(Debug)]
enum IsolatedArgumentLabels {
    Public,
    Exact(Vec<Label>),
    Uniform(Label),
}

#[derive(Debug)]
struct IsolatedCallLabels {
    receiver: Label,
    arguments: IsolatedArgumentLabels,
}

/// Trailing arguments of a synthetic call site whose list does not fit a
/// register frame (bd-9vouw.50). Register `max_registers + i` of the frame at
/// `register_base` reads `values[i]` and `labels[i]`, so an argument range
/// that starts inside the frame runs on past its end, and every consumer
/// (formals, rest parameter, `arguments`, native builtins) reads it through
/// the ordinary register accessors.
#[derive(Debug)]
struct ArgumentOverflow {
    register_base: usize,
    values: Vec<Value>,
    labels: Vec<Label>,
    /// Charge carried in `InterpreterCore::argument_overflow_bytes`.
    bytes: u64,
}

// ---------------------------------------------------------------------------
// Promise combinator state (Promise.all / race / allSettled / any)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum PromiseCombinatorState {
    All(crate::promise_model::PromiseAllTracker),
    AllSettled(crate::promise_model::PromiseAllSettledTracker),
    Race(crate::promise_model::PromiseRaceTracker),
    Any(crate::promise_model::PromiseAnyTracker),
}

impl PromiseCombinatorState {
    fn result_promise(&self) -> crate::promise_model::PromiseHandle {
        match self {
            Self::All(tracker) => tracker.result_promise,
            Self::AllSettled(tracker) => tracker.result_promise,
            Self::Race(tracker) => tracker.result_promise,
            Self::Any(tracker) => tracker.result_promise,
        }
    }

    /// Additional retained payload of one still-live element reaction. The
    /// map/string charges match the model trackers' resident-memory algebra.
    fn observation_memory_growth(
        &self,
        index: u32,
        kind: crate::promise_model::ReactionKind,
        value: &crate::object_model::JsValue,
    ) -> Option<u64> {
        let entry_bytes = MEMORY_ESTIMATE_MAP_ENTRY_BYTES
            .saturating_add(crate::promise_model::estimate_js_value_memory_bytes(value));
        let rejected = kind == crate::promise_model::ReactionKind::Reject;
        match self {
            Self::All(tracker) if !tracker.settled && index < tracker.total => {
                if rejected {
                    Some(0)
                } else if !tracker.values.contains_key(&index) {
                    Some(entry_bytes)
                } else {
                    None
                }
            }
            Self::AllSettled(tracker)
                if index < tracker.total && !tracker.outcomes.contains_key(&index) =>
            {
                let status = if rejected { "rejected" } else { "fulfilled" };
                Some(
                    entry_bytes
                        .saturating_add(MEMORY_ESTIMATE_STRING_BASE_BYTES)
                        .saturating_add(status.len() as u64),
                )
            }
            Self::Race(tracker) if !tracker.settled => Some(0),
            Self::Any(tracker) if !tracker.settled && index < tracker.total => {
                if !rejected {
                    Some(0)
                } else if !tracker.errors.contains_key(&index) {
                    Some(entry_bytes)
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PromiseCombinatorKind {
    All,
    AllSettled,
    Race,
    Any,
}

#[derive(Debug, Clone, Copy)]
enum PromiseReactionKind {
    Then,
    Catch,
    Finally,
}

#[derive(Debug, Clone)]
struct PromiseCombinatorWatcher {
    combinator_id: u64,
    index: u32,
}

/// JIT statistics for hot path detection.
#[derive(Debug, Clone, PartialEq)]
pub struct JitStatistics(pub usize, pub usize, pub u64, pub u64, pub u64);

impl JitStatistics {
    pub fn function_counts_len(&self) -> usize {
        self.0
    }
    pub fn loop_counts_len(&self) -> usize {
        self.1
    }
    pub fn hot_threshold(&self) -> u64 {
        self.2
    }
    pub fn eviction_counter(&self) -> u64 {
        self.3
    }
    pub fn total_function_calls(&self) -> u64 {
        self.4
    }
}

#[derive(Debug, Clone)]
struct LoopIterationCounters {
    storage: LoopIterationCounterStorage,
}

#[derive(Debug, Clone)]
enum LoopIterationCounterStorage {
    Inline(Vec<(usize, u64)>),
    Hashed(BTreeMap<usize, u64>),
}

impl Default for LoopIterationCounters {
    fn default() -> Self {
        Self {
            storage: LoopIterationCounterStorage::Inline(Vec::new()),
        }
    }
}

impl LoopIterationCounters {
    fn increment(&mut self, instruction_index: usize) -> u64 {
        match &mut self.storage {
            LoopIterationCounterStorage::Inline(entries) => {
                if let Some((_, count)) = entries
                    .iter_mut()
                    .find(|(index, _)| *index == instruction_index)
                {
                    *count += 1;
                    return *count;
                }

                if entries.len() < JIT_LOOP_COUNTER_INLINE_CAPACITY {
                    entries.push((instruction_index, 1));
                    return 1;
                }

                let mut promoted = BTreeMap::new();
                for (index, count) in entries.drain(..) {
                    promoted.insert(index, count);
                }
                let count = promoted.entry(instruction_index).or_insert(0);
                *count += 1;
                let updated = *count;
                self.storage = LoopIterationCounterStorage::Hashed(promoted);
                updated
            }
            LoopIterationCounterStorage::Hashed(entries) => {
                let count = entries.entry(instruction_index).or_insert(0);
                *count += 1;
                *count
            }
        }
    }

    fn get(&self, instruction_index: usize) -> u64 {
        match &self.storage {
            LoopIterationCounterStorage::Inline(entries) => entries
                .iter()
                .find_map(|(index, count)| (*index == instruction_index).then_some(*count))
                .unwrap_or(0),
            LoopIterationCounterStorage::Hashed(entries) => {
                entries.get(&instruction_index).copied().unwrap_or(0)
            }
        }
    }

    fn len(&self) -> usize {
        match &self.storage {
            LoopIterationCounterStorage::Inline(entries) => entries.len(),
            LoopIterationCounterStorage::Hashed(entries) => entries.len(),
        }
    }

    fn retain_above(&mut self, threshold: u64) {
        match &mut self.storage {
            LoopIterationCounterStorage::Inline(entries) => {
                entries.retain(|(_, count)| *count > threshold);
            }
            LoopIterationCounterStorage::Hashed(entries) => {
                entries.retain(|_, count| *count > threshold);
                if entries.len() <= JIT_LOOP_COUNTER_INLINE_CAPACITY {
                    let inline = entries
                        .iter()
                        .map(|(index, count)| (*index, *count))
                        .collect();
                    self.storage = LoopIterationCounterStorage::Inline(inline);
                }
            }
        }
    }

    fn clear(&mut self) {
        match &mut self.storage {
            LoopIterationCounterStorage::Inline(entries) => entries.clear(),
            LoopIterationCounterStorage::Hashed(entries) => entries.clear(),
        }
    }

    #[cfg(test)]
    fn is_hashed(&self) -> bool {
        matches!(self.storage, LoopIterationCounterStorage::Hashed(_))
    }
}

// Allow destructuring as (usize, usize, u64, u64)
impl From<JitStatistics> for (usize, usize, u64, u64) {
    fn from(value: JitStatistics) -> Self {
        (value.0, value.1, value.2, value.3)
    }
}

// Allow direct destructuring patterns
impl JitStatistics {
    pub fn destructure(self) -> (usize, usize, u64, u64) {
        (self.0, self.1, self.2, self.3)
    }
}

#[cfg(test)]
mod loop_iteration_counter_tests {
    use super::*;

    #[test]
    fn loop_iteration_counters_stay_inline_for_common_small_loop_sets() {
        let mut counters = LoopIterationCounters::default();

        for index in 0..JIT_LOOP_COUNTER_INLINE_CAPACITY {
            assert_eq!(counters.increment(index), 1);
        }
        assert_eq!(counters.increment(3), 2);

        assert_eq!(counters.len(), JIT_LOOP_COUNTER_INLINE_CAPACITY);
        assert_eq!(counters.get(3), 2);
        assert_eq!(counters.get(999), 0);
        assert!(!counters.is_hashed());
    }

    #[test]
    fn loop_iteration_counters_promote_and_retain_counts() {
        let mut counters = LoopIterationCounters::default();

        for index in 0..=JIT_LOOP_COUNTER_INLINE_CAPACITY {
            assert_eq!(counters.increment(index), 1);
        }
        assert!(counters.is_hashed());

        for _ in 0..11 {
            counters.increment(2);
        }
        counters.retain_above(10);

        assert_eq!(counters.len(), 1);
        assert_eq!(counters.get(2), 12);
        assert_eq!(counters.get(1), 0);
        assert!(!counters.is_hashed());
    }
}

// ---------------------------------------------------------------------------
// SeedTrackedField — type discipline for PERF-H2.2
// ---------------------------------------------------------------------------

/// Type wrapper for execution seed surface fields. NO DerefMut.
/// Direct field access is internal; mutation only via mutate_<field> helpers.
pub(crate) struct SeedTrackedField<T> {
    value: T,
}

impl<T> SeedTrackedField<T> {
    pub(crate) fn new(value: T) -> Self {
        Self { value }
    }
}

impl<T> std::ops::Deref for SeedTrackedField<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.value
    }
}

// INTENTIONALLY NO DerefMut.

// ---------------------------------------------------------------------------
// ExecutionSeed — lazy materialization for PERF-H2.2
// ---------------------------------------------------------------------------

/// Execution seed for lazy materialization optimization.
pub enum ExecutionSeed {
    Lazy {
        epoch: u64,
        max_regs: u32,
    },
    Materialized {
        registers: Vec<Value>,
        heap: Heap,
        function_prototypes: BTreeMap<(ContentHash, u32), ObjectId>,
        builtin_prototypes: BTreeMap<String, ObjectId>,
        symbol_state: RuntimeSymbolState,
    },
}

#[derive(Default)]
struct ExecutionSeedReservationLedger {
    live_reserved_bytes: std::cell::Cell<u64>,
    accounting_fault: std::cell::Cell<bool>,
}

#[derive(Clone)]
struct ExecutionSeedHandle(std::rc::Rc<ExecutionSeedShared>);

struct ExecutionSeedShared {
    state: std::cell::RefCell<Box<ExecutionSeed>>,
    snapshot_bytes: u64,
    reserved_bytes: std::cell::Cell<u64>,
    registered: std::cell::Cell<bool>,
    reservation_ledger: std::rc::Weak<ExecutionSeedReservationLedger>,
}

impl Drop for ExecutionSeedShared {
    fn drop(&mut self) {
        let Some(ledger) = self.reservation_ledger.upgrade() else {
            return;
        };
        let reserved_bytes = if self.registered.get() {
            self.reserved_bytes
                .get()
                .saturating_sub(InterpreterCore::pending_execution_seed_entry_bytes())
        } else {
            self.reserved_bytes.get()
        };
        match ledger.live_reserved_bytes.get().checked_sub(reserved_bytes) {
            Some(next) => ledger.live_reserved_bytes.set(next),
            None => {
                ledger.accounting_fault.set(true);
                ledger.live_reserved_bytes.set(u64::MAX);
            }
        }
    }
}

impl ExecutionSeedHandle {
    fn is_owned_by(&self, ledger: &std::rc::Rc<ExecutionSeedReservationLedger>) -> bool {
        self.0
            .reservation_ledger
            .upgrade()
            .is_some_and(|owner| std::rc::Rc::ptr_eq(&owner, ledger))
    }

    #[cfg(test)]
    fn is_lazy(&self) -> bool {
        matches!(&**self.0.state.borrow(), ExecutionSeed::Lazy { .. })
    }

    #[cfg(test)]
    fn inspect<R>(&self, inspect: impl FnOnce(&ExecutionSeed) -> R) -> R {
        inspect(&self.0.state.borrow())
    }
}

// ---------------------------------------------------------------------------
// InterpreterCore — shared execution engine
// ---------------------------------------------------------------------------

/// bd-3894s slice (2d): the readable-stream emission phase for an HTTP
/// `IncomingMessage` response. The single-shot response body is delivered as one
/// `'data'` chunk (only when non-empty — Node emits no `'data'` for an empty body)
/// followed by `'end'`, each on its own event-loop turn so a `res.on('data', …);
/// res.on('end', …)` pair registered inside the response callback observes Node's
/// data→end ordering.
#[derive(Debug, Clone, Copy)]
enum StreamEventPhase {
    Data,
    End,
}

/// bd-3894s slice (2d): a deferred readable-stream emission scheduled as an
/// `IoCompletion` macrotask. Carries the target `IncomingMessage` object and the
/// phase to emit; the listener closures are looked up from `event_listeners` when
/// the macrotask fires, so they reflect every `res.on(...)` registered up to that
/// turn (the response callback that registers them ran on an earlier turn).
#[derive(Debug, Clone, Copy)]
struct PendingStreamEmission {
    object_id: ObjectId,
    phase: StreamEventPhase,
}

/// One interpreter-owned loopback listener. Only listeners created by the
/// current JS execution can be reached; no OS bind or ambient network
/// authority is involved (bd-7qwej).
#[derive(Debug, Clone)]
struct LoopbackServerState {
    address: String,
    port: Option<u16>,
    generation: u64,
    listening: bool,
    active_connections: BTreeSet<ObjectId>,
    close_requested: bool,
    close_scheduled: bool,
    tls: Option<HermeticTlsServerState>,
    lifecycle_label: Label,
}

/// TLS-shaped metadata layered over an engine-owned loopback server. This is
/// deliberately not a rustls/OS socket: it models Node's verification and
/// negotiated-session API without granting ambient network authority
/// (bd-70cv1).
#[derive(Debug, Clone)]
struct HermeticTlsServerState {
    has_certificate: bool,
    certificate_der: Vec<u8>,
    request_cert: bool,
    reject_unauthorized: bool,
    alpn_protocols: Vec<String>,
}

#[derive(Debug, Clone)]
struct LoopbackBufferedData {
    bytes: Vec<u8>,
    label: Label,
}

/// Authoritative state for a hermetic loopback socket. Public fields such as
/// `bytesRead` are mirrored onto the heap for Node-shaped observation, while
/// peer linkage and queued bytes remain unforgeable engine state.
#[derive(Debug, Clone)]
struct LoopbackSocketState {
    peer: Option<ObjectId>,
    owner_server: Option<ObjectId>,
    owner_server_generation: Option<u64>,
    paused: bool,
    encoding_utf8: bool,
    local_ended: bool,
    remote_ended: bool,
    destroyed: bool,
    close_scheduled: bool,
    bytes_read: u64,
    bytes_written: u64,
    pending_data: VecDeque<LoopbackBufferedData>,
    pending_end: bool,
    pending_outbound: VecDeque<LoopbackBufferedData>,
    pending_outbound_end: bool,
    tls: Option<HermeticTlsSocketState>,
    lifecycle_label: Label,
    /// Node keeps `socket.end(callback)` outside the EventEmitter finish
    /// listener set: the callback is a dedicated write-completion carrier,
    /// invisible to `listeners("finish")`/`rawListeners("finish")`
    /// (bd-asw4m.5). Consumed once when the finish emission completes.
    end_completion_callback: Option<Value>,
}

/// TLS session observations that cannot be forged through guest heap writes.
/// Application bytes still use the loopback socket queues; successful
/// verification is required before those queues are linked to a peer.
#[derive(Debug, Clone)]
struct HermeticTlsSocketState {
    server_side: bool,
    handshake_complete: bool,
    reject_unauthorized: bool,
    servername: Option<String>,
    authorized: bool,
    authorization_error: Option<String>,
    alpn_protocols: Vec<String>,
    negotiated_alpn: Option<String>,
    peer_certificate_der: Vec<u8>,
}

/// Deferred loopback lifecycle/data actions dispatched on the existing
/// deterministic `IoCompletion` lane. Keeping these out of the guest heap
/// preserves event ordering and prevents forged transport state.
#[derive(Debug, Clone)]
enum PendingLoopbackTask {
    Listening {
        server: ObjectId,
        generation: u64,
    },
    Connect {
        client: ObjectId,
        server: ObjectId,
        generation: u64,
    },
    Data {
        target: ObjectId,
        bytes: Vec<u8>,
        label: Label,
    },
    End {
        target: ObjectId,
        label: Label,
    },
    Close {
        target: ObjectId,
        had_error: bool,
        label: Label,
    },
    ServerClose {
        server: ObjectId,
        generation: u64,
        label: Label,
    },
    Error {
        target: ObjectId,
        code: String,
        label: Label,
        close_after: bool,
    },
}

/// Authoritative classification for every deterministic port allocated during
/// one execution. Closed entries deliberately remain until reset: a request to
/// a formerly internal port is an internal ECONNREFUSED, never an opportunity
/// to escape through the external network provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoopbackPortState {
    Live { server: ObjectId, generation: u64 },
    Closed { generation: u64 },
}

#[derive(Debug, Clone)]
struct HttpHeaderValue {
    original_name: String,
    /// Node preserves array-valued response headers for `getHeader()`, while
    /// request/response serialization folds them with `, `. Keep both shapes
    /// so the guest-visible value is not reconstructed from a lossy string.
    array_values: Option<Vec<String>>,
    value: String,
}

type HttpHeaders = BTreeMap<String, HttpHeaderValue>;

#[derive(Debug, Clone)]
struct HttpServerState {
    lifecycle_label: Label,
}

#[derive(Debug, Clone)]
struct HttpClientRequestState {
    host: String,
    port: u16,
    use_tls: bool,
    internal_loopback_candidate: bool,
    path: String,
    method: String,
    headers: HttpHeaders,
    body: Vec<u8>,
    ended: bool,
    response_callback: Option<u32>,
    lifecycle_label: Label,
    /// bd-9vouw.8: the label of what goes on the wire (URL, options,
    /// headers, body chunks), without the request object's own floor. The
    /// external egress checks this one.
    egress_label: Label,
}

#[derive(Debug, Clone)]
struct ResolvedHttpRequest {
    host: String,
    port: u16,
    use_tls: bool,
    internal_loopback_candidate: bool,
    path: String,
    method: String,
    headers: HttpHeaders,
    response_callback: Option<u32>,
}

#[derive(Debug, Clone)]
struct HttpIncomingMessageState {
    body: Vec<u8>,
    encoding_utf8: bool,
    delivered: bool,
    close_after_end: bool,
    server_completion: Option<HttpServerCompletion>,
    lifecycle_label: Label,
}

#[derive(Debug, Clone, Copy)]
struct HttpServerCompletion {
    server: ObjectId,
    generation: u64,
    response: ObjectId,
}

#[derive(Debug, Clone)]
struct HttpServerResponseState {
    client_request: ObjectId,
    server: ObjectId,
    server_generation: u64,
    request_method: String,
    status_code: u16,
    status_message: String,
    headers: HttpHeaders,
    body: Vec<u8>,
    ended: bool,
    lifecycle_label: Label,
}

#[derive(Debug, Clone)]
enum PendingHttpTask {
    DispatchRequest {
        request: ObjectId,
        server: ObjectId,
        generation: u64,
    },
    DeliverResponse {
        request: ObjectId,
        message: ObjectId,
    },
    DeliverExternalResponse {
        request: ObjectId,
        response: Option<ObjectId>,
    },
    MessageData {
        message: ObjectId,
    },
    MessageEnd {
        message: ObjectId,
    },
    MessageClose {
        message: ObjectId,
    },
    ClientError {
        request: ObjectId,
        code: String,
        label: Label,
    },
    EmitLegacyEvent {
        target: ObjectId,
        event: String,
        arguments: Vec<Value>,
        leading_callback: Option<u32>,
        label: Label,
    },
}

#[derive(Debug, Clone, Default)]
struct ProcessCallOptions {
    cwd: Option<String>,
    env: BTreeMap<String, String>,
    input: Vec<u8>,
    encoding: Option<String>,
    shell: bool,
    stdio: ProcessStdio,
    timeout_millis: Option<u64>,
    max_buffer: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChildProcessStreamKind {
    Stdout,
    Stderr,
    /// Guest-writable stdin facade (bd-m42c2). Registered so `write`/`end`
    /// can resolve their owning child; it never emits lifecycle events.
    Stdin,
}

#[derive(Debug)]
struct CompletedChildProcessState {
    settled: bool,
    stdout: Value,
    stdout_has_data: bool,
    stderr: Value,
    stderr_has_data: bool,
    exit_code: Value,
    signal: Value,
    error: Option<Value>,
    scheduled_events: BTreeSet<String>,
}

#[derive(Debug)]
struct PendingChildProcessTask {
    child: ObjectId,
    handle: String,
    callback: Option<u32>,
    callback_label: Label,
    callback_encoding: Option<String>,
    options: ProcessCallOptions,
}

/// Current phase of one finite `Readable.from` pump.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadableFromPumpPhase {
    Data,
    End,
    DestroyError,
    Close,
    SettleToArray,
}

/// Deferred result for `Readable.from(...).toArray()`. The result array is
/// materialized when consumption begins, but the Promise is intentionally not
/// fulfilled until the Close pump phase has emitted `close`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ReadableToArrayWaiter {
    promise: crate::promise_model::PromiseHandle,
    result: ObjectId,
    label: Label,
}

/// Authenticated, engine-owned WHATWG URL state (bd-8y0gs). The guest heap
/// carries only the opaque object identity; every observable field is derived
/// from this canonical serialization so writing forgeable `__type`-style
/// properties cannot manufacture a URL instance.
#[derive(Debug, Clone, PartialEq, Eq)]
struct UrlRuntimeState {
    href: String,
    search_params: ObjectId,
    lifecycle_label: Label,
}

/// Ordered duplicate-preserving URLSearchParams storage. A linked instance
/// updates its owning URL transactionally after every mutation; standalone
/// instances leave `owner_url` empty.
#[derive(Debug, Clone, PartialEq, Eq)]
struct UrlSearchParamsRuntimeState {
    pairs: Vec<(String, String)>,
    owner_url: Option<ObjectId>,
    lifecycle_label: Label,
}

/// Authenticated execution-local state for the hermetic primary-process
/// `cluster` facade. The key is the facade object id; retaining the current
/// settings id here makes both objects non-forgeable provenance carriers even
/// though the guest-visible `settings` property is an ordinary heap mirror.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ClusterRuntimeState {
    settings: ObjectId,
    lifecycle_label: Label,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum UrlSearchParamsMutation {
    Append(String, String),
    Sort,
    Delete(String),
    Set(String, String),
}

/// One engine-owned buffered chunk. Keeping the value and its IFC label in
/// the same side-table record prevents guest writes to public stream mirrors
/// from forging either queue contents or provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ReadableBufferedChunk {
    value: Value,
    label: Label,
    /// Object-mode chunks count as one; byte-mode strings/Buffers count bytes.
    units: usize,
}

/// Finite pure-compute readable state. The cursor and flow-control bit stay
/// outside the JS heap so guest property writes cannot forge stream progress.
/// Within the supported array subset, own indexed elements and length are read
/// lazily so ordinary source mutation is observed between pump turns. Custom
/// iterators, accessors, and inherited indexed properties remain fail-closed.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ReadableFromState {
    source: Value,
    /// Generic `new Readable(...)` instances accept only explicit `push(null)`
    /// termination in this slice; they must not treat their placeholder source
    /// as an already-exhausted finite iterable when resumed.
    push_only: bool,
    object_mode: bool,
    high_water_mark: usize,
    read_callback: Option<Value>,
    buffer: VecDeque<ReadableBufferedChunk>,
    buffered_length: usize,
    eof_requested: bool,
    data_readable_pending: bool,
    eof_readable_pending: bool,
    read_callback_active: bool,
    decode_utf8: bool,
    utf8_pending: Vec<u8>,
    destroy_requested: bool,
    destroy_error: Option<Value>,
    next_index: usize,
    phase: ReadableFromPumpPhase,
    flowing: bool,
    paused: bool,
    /// Engine-owned evidence that a non-flowing `read()` consumed at least
    /// one buffered chunk. PassThrough finalization uses this together with
    /// an empty queue to distinguish a synchronous pull drain from a passive
    /// or partial `readable` listener without trusting guest-visible mirrors.
    nonflowing_read_consumed: bool,
    lifecycle_label: Label,
    to_array_waiter: Option<ReadableToArrayWaiter>,
}

/// Compact engine-owned provenance retained after the live Readable kernel
/// releases its queue and callbacks. Ordinary terminal heap mirrors remain
/// guest-mutable compatibility data and are never trusted as IFC authority.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ReadableTerminalState {
    lifecycle_label: Label,
}

/// Exact scheduler headroom retained across one guest Readable callback.
/// Re-entrant stream operations cannot materialize the successor while the
/// callback is active without violating registration order, so they record
/// that a successor was requested for conversion on callback return.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReadablePumpReservation {
    bytes: u64,
    requested: bool,
}

/// Authenticated ownership edge for one bounded `Readable.pipe` link. The
/// token is copied into both internal listener builtins and never reused
/// within the interpreter process, so a retained listener cannot target an
/// ObjectId that a later execution restored for an unrelated stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReadablePipeLink {
    destination: ObjectId,
    token: u32,
}

/// Completion state for one engine-owned Writable write record. The token is
/// checked by the internal callback builtin so a retained or duplicated guest
/// callback cannot complete a later write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WritableWriteStatus {
    Pending,
    Active(u32),
    Completed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WritableWriteRecord {
    value: Value,
    label: Label,
    units: usize,
    callback: Option<WritableCallbackRecord>,
    status: WritableWriteStatus,
    /// Whether this record completed under the stream's one shared terminal
    /// write error. Keeping only a bit avoids duplicating an attacker-sized
    /// error value into every queued record at the memory ceiling.
    completion_failed: bool,
}

/// Allocation-exact split FIFO for live Writable records. `LinkedList` gives
/// every append one independently charged node, so a transaction never needs
/// to clone or grow an allocator-rounded queue before its budget preflight.
///
/// Completed records remain in registration order for deferred callbacks, but
/// they must not sit in front of the active/pending scheduler cursor. Keeping
/// completed and ready nodes in separate lists makes activation, completion,
/// callback drainage, pending-token accounting, and hot-path memory accounting
/// constant time. Moving the ready front uses `split_off(1)` plus `append`, so
/// the already-charged linked-list node is relinked without another allocation.
#[allow(clippy::linkedlist)]
#[derive(Debug, Default, PartialEq, Eq)]
struct WritableWriteQueue {
    completed: LinkedList<WritableWriteRecord>,
    ready: LinkedList<WritableWriteRecord>,
    retained_bytes: u64,
    #[cfg(test)]
    scheduler_steps: u64,
}

impl WritableWriteQueue {
    fn len(&self) -> usize {
        self.completed.len().saturating_add(self.ready.len())
    }

    fn is_empty(&self) -> bool {
        self.completed.is_empty() && self.ready.is_empty()
    }

    fn retained_bytes(&self) -> u64 {
        self.retained_bytes
    }

    fn recompute_retained_bytes(&self) -> u64 {
        self.iter().fold(0u64, |total, record| {
            total.saturating_add(InterpreterCore::estimate_writable_write_record_bytes(
                record,
            ))
        })
    }

    fn pending_len(&self) -> usize {
        self.ready
            .len()
            .saturating_sub(usize::from(self.ready.front().is_some_and(|record| {
                matches!(
                    record.status,
                    WritableWriteStatus::Active(_) | WritableWriteStatus::Completed
                )
            })))
    }

    fn iter(
        &self,
    ) -> std::iter::Chain<
        std::collections::linked_list::Iter<'_, WritableWriteRecord>,
        std::collections::linked_list::Iter<'_, WritableWriteRecord>,
    > {
        self.completed.iter().chain(self.ready.iter())
    }

    fn iter_mut(
        &mut self,
    ) -> std::iter::Chain<
        std::collections::linked_list::IterMut<'_, WritableWriteRecord>,
        std::collections::linked_list::IterMut<'_, WritableWriteRecord>,
    > {
        self.completed.iter_mut().chain(self.ready.iter_mut())
    }

    fn front(&self) -> Option<&WritableWriteRecord> {
        self.completed.front().or_else(|| self.ready.front())
    }

    fn ready_front(&self) -> Option<&WritableWriteRecord> {
        self.ready.front()
    }

    fn push_back(&mut self, record: WritableWriteRecord) {
        let record_bytes = InterpreterCore::estimate_writable_write_record_bytes(&record);
        self.retained_bytes = self.retained_bytes.saturating_add(record_bytes);
        self.ready.push_back(record);
        self.record_scheduler_steps(1);
    }

    fn has_active_token(&self, token: u32) -> bool {
        self.ready
            .front()
            .is_some_and(|record| record.status == WritableWriteStatus::Active(token))
    }

    fn active_label(&self, token: u32) -> Option<&Label> {
        self.ready
            .front()
            .filter(|record| record.status == WritableWriteStatus::Active(token))
            .map(|record| &record.label)
    }

    fn has_active(&self) -> bool {
        self.ready
            .front()
            .is_some_and(|record| matches!(record.status, WritableWriteStatus::Active(_)))
    }

    fn has_completed(&self) -> bool {
        !self.completed.is_empty()
            || self
                .ready
                .front()
                .is_some_and(|record| record.status == WritableWriteStatus::Completed)
    }

    fn activate_front(&mut self, token: u32) -> bool {
        let Some(record) = self.ready.front_mut() else {
            return false;
        };
        if record.status != WritableWriteStatus::Pending {
            return false;
        }
        record.status = WritableWriteStatus::Active(token);
        self.record_scheduler_steps(1);
        true
    }

    fn rollback_active(&mut self, token: u32) -> bool {
        let Some(record) = self.ready.front_mut() else {
            return false;
        };
        if record.status != WritableWriteStatus::Active(token) {
            return false;
        }
        record.status = WritableWriteStatus::Pending;
        self.record_scheduler_steps(1);
        true
    }

    fn complete_active(&mut self, token: u32, completion_failed: bool) -> Option<usize> {
        let record = self.ready.front_mut()?;
        if record.status != WritableWriteStatus::Active(token) {
            return None;
        }
        let units = record.units;
        record.status = WritableWriteStatus::Completed;
        record.completion_failed = completion_failed;
        self.move_ready_front_to_completed();
        self.record_scheduler_steps(1);
        Some(units)
    }

    fn complete_all_ready_failed(&mut self) {
        let visited = u64::try_from(self.ready.len()).unwrap_or(u64::MAX);
        for record in &mut self.ready {
            record.status = WritableWriteStatus::Completed;
            record.completion_failed = true;
        }
        self.completed.append(&mut self.ready);
        self.record_scheduler_steps(visited);
    }

    fn all_completed(&self) -> bool {
        self.ready
            .iter()
            .all(|record| record.status == WritableWriteStatus::Completed)
    }

    fn active_units(&self) -> usize {
        self.ready.front().map_or(0, |record| {
            if matches!(record.status, WritableWriteStatus::Active(_)) {
                record.units
            } else {
                0
            }
        })
    }

    fn pop_completed_front(&mut self) -> Option<WritableWriteRecord> {
        let record = if let Some(record) = self.completed.pop_front() {
            record
        } else if self
            .ready
            .front()
            .is_some_and(|record| record.status == WritableWriteStatus::Completed)
        {
            // Unit tests sometimes arrange a completed prefix directly. The
            // production completion path relinks it into `completed` first.
            self.ready.pop_front()?
        } else {
            return None;
        };
        let record_bytes = InterpreterCore::estimate_writable_write_record_bytes(&record);
        self.retained_bytes = self.retained_bytes.saturating_sub(record_bytes);
        self.record_scheduler_steps(1);
        Some(record)
    }

    fn normalize_completed_prefix(&mut self) {
        while self
            .ready
            .front()
            .is_some_and(|record| record.status == WritableWriteStatus::Completed)
        {
            self.move_ready_front_to_completed();
            self.record_scheduler_steps(1);
        }
        // This recovery path is reachable only from tests that construct
        // internal queue states directly. Production completion relinks the
        // node at the status transition.
    }

    fn move_ready_front_to_completed(&mut self) {
        debug_assert!(!self.ready.is_empty());
        let tail = self.ready.split_off(1);
        self.completed.append(&mut self.ready);
        self.ready = tail;
    }

    #[cfg(test)]
    fn scheduler_steps(&self) -> u64 {
        self.scheduler_steps
    }

    fn record_scheduler_steps(&mut self, steps: u64) {
        #[cfg(test)]
        {
            self.scheduler_steps = self.scheduler_steps.saturating_add(steps);
        }
        #[cfg(not(test))]
        let _ = steps;
    }
}

#[cfg(test)]
impl std::ops::Index<usize> for WritableWriteQueue {
    type Output = WritableWriteRecord;

    fn index(&self, index: usize) -> &Self::Output {
        self.iter()
            .nth(index)
            .expect("Writable write queue test index was validated")
    }
}

#[cfg(test)]
impl std::ops::IndexMut<usize> for WritableWriteQueue {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        self.iter_mut()
            .nth(index)
            .expect("Writable write queue test index was validated")
    }
}

impl<'a> IntoIterator for &'a WritableWriteQueue {
    type Item = &'a WritableWriteRecord;
    type IntoIter = std::iter::Chain<
        std::collections::linked_list::Iter<'a, WritableWriteRecord>,
        std::collections::linked_list::Iter<'a, WritableWriteRecord>,
    >;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> IntoIterator for &'a mut WritableWriteQueue {
    type Item = &'a mut WritableWriteRecord;
    type IntoIter = std::iter::Chain<
        std::collections::linked_list::IterMut<'a, WritableWriteRecord>,
        std::collections::linked_list::IterMut<'a, WritableWriteRecord>,
    >;

    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WritableCallbackRecord {
    value: Value,
    label: Label,
    /// Module active when a raw function callback was registered. Closure
    /// values are still resolved through `closure_module_origins` at call
    /// time, because their owner may differ from their registration site.
    module_specifier: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WritableEndCallbackRecord {
    callback: WritableCallbackRecord,
    registered_after_end: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WritableFinalStatus {
    NotStarted,
    Active(u32),
    Done,
}

/// Deferred lifecycle work has its own deterministic checkpoint ahead of
/// microtasks and Immediate macrotasks. This matches Node/Bun's stream-tick
/// ordering without pretending pure stream bookkeeping is host I/O.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WritableTickPhase {
    Callbacks,
    Finish,
    Error,
    Close,
    Release,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WritableErrorOrigin {
    Write,
    Final,
    Destroy,
}

/// Authenticated stream role. Public `__type` mirrors remain guest-mutable,
/// so every dual-stream branch consults this fixed-size engine-owned marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WritableStreamFlavor {
    Writable,
    PassThrough,
    Transform,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WritableTerminalCallbackError {
    EndAfterFinish,
    EndAfterDestroy,
    WriteAfterFinish,
    WriteAfterDestroy,
}

impl WritableTerminalCallbackError {
    fn message(self) -> &'static str {
        match self {
            Self::EndAfterFinish => "Cannot call end after a stream was finished",
            Self::EndAfterDestroy => "Cannot call end after a stream was destroyed",
            Self::WriteAfterFinish => "write after end",
            Self::WriteAfterDestroy => "Cannot call write after a stream was destroyed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WritableTerminalCallbackRecord {
    callback: WritableCallbackRecord,
    error: WritableTerminalCallbackError,
}

/// Accounted, engine-owned state retained after the live Writable kernel has
/// released its queues and implementation callbacks. Keeping this separate
/// from `writable_streams` prevents closed instances from inflating every
/// active-stream scheduler scan while preserving branding, state views, IFC
/// provenance, and deterministic post-close callback delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
struct WritableTerminalState {
    object_mode: bool,
    high_water_mark: usize,
    end_requested: bool,
    finished: bool,
    buffered_length: usize,
    cork_depth: u32,
    /// `end(callback)` after an error-bearing destroy is settled with the
    /// destroyed-stream error. Bun ignores this callback after a no-error
    /// destroy, so that distinction must survive live-state release.
    accepts_late_end_callback: bool,
    #[allow(clippy::linkedlist)]
    callbacks: LinkedList<WritableTerminalCallbackRecord>,
    tick_sequence: Option<u64>,
    lifecycle_label: Label,
}

/// Authoritative Writable state. Public `writable*` properties are mirrors
/// only; guest writes or deletions cannot forge progress, callback tokens, or
/// lifecycle completion.
#[derive(Debug, PartialEq, Eq)]
struct WritableState {
    flavor: WritableStreamFlavor,
    object_mode: bool,
    high_water_mark: usize,
    write_callback: Option<Value>,
    final_callback: Option<Value>,
    writes: WritableWriteQueue,
    buffered_length: usize,
    need_drain: bool,
    /// Nested `cork()` depth. This fixed-size field is covered by the
    /// conservative Writable base charge.
    cork_depth: u32,
    end_requested: bool,
    /// Synchronous destroy brand retained until deferred close/release.
    destroy_requested: bool,
    // A node-counted list makes each FIFO append one deterministic charged
    // allocation. A VecDeque cannot provide a contractual upper bound for the
    // capacity returned by `try_reserve_exact`, which makes atomic budget
    // preflight impossible at the memory ceiling.
    #[allow(clippy::linkedlist)]
    end_callbacks: LinkedList<WritableEndCallbackRecord>,
    /// Number of callbacks that belonged to the terminal batch when the
    /// current finish/write-error phase began. Re-entrant `end(callback)`
    /// registrations append to the same FIFO but are intentionally excluded
    /// from the in-flight batch, matching Node's post-finish error ordering.
    end_callback_batch_remaining: usize,
    /// Late callbacks that were already queued when a successful terminal
    /// callback re-entered `destroy()`. They still observe the finished-stream
    /// error before the destroy error event; callbacks registered after that
    /// destroy remain outside this fixed batch and run after close.
    finished_end_callback_batch_remaining: usize,
    final_status: WritableFinalStatus,
    prefinish_emitted: bool,
    /// Becomes true before the first success `end(callback)` runs, matching
    /// Node/Bun's observable `writableFinished` state during that callback.
    finished: bool,
    terminal_error: Option<(Value, Label)>,
    terminal_error_origin: Option<WritableErrorOrigin>,
    /// Prevents a re-entrant `destroy()` from emitting an already-observed
    /// terminal error a second time.
    terminal_error_emitted: bool,
    tick_phase: WritableTickPhase,
    /// Monotonic scheduling sequence for the next internal stream checkpoint.
    /// Keeping it in the fixed-size, already-accounted state preserves FIFO
    /// scheduling without retaining a second allocation-owning queue.
    tick_sequence: Option<u64>,
    /// Sequence reserved by an engine-owned PassThrough `_final` before its
    /// synchronous `prefinish`. It is not scheduler-visible until the
    /// authenticated final token completes immediately or after readable
    /// `end`, so re-entrant/unrelated work cannot strand that token.
    deferred_final_tick_sequence: Option<u64>,
    inside_write_invocation: bool,
    lifecycle_label: Label,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum StreamPipelineCompletion {
    Callback(Value),
    Promise(crate::promise_model::PromiseHandle),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamPipelinePhase {
    Running,
    Destroying,
    Settling,
}

/// One authenticated linear pipeline. Internal EventEmitter listeners carry
/// the process-lifetime token and bound stage id; the close barrier,
/// completion target, first error, and IFC provenance never enter guest state.
#[derive(Debug, Clone, PartialEq, Eq)]
struct StreamPipelineState {
    stages: Vec<ObjectId>,
    pending_close: Vec<ObjectId>,
    completion: StreamPipelineCompletion,
    registration_label: Label,
    first_error: Option<(Value, Label)>,
    phase: StreamPipelinePhase,
}

/// One listener in the interpreter-wide EventEmitter side table (bd-2dmnn).
///
/// The pre-existing HTTP stream emitter stored bare closure ids. Keeping the
/// listener as a [`Value`] lets the same table represent ordinary functions and
/// builtins without creating a second event subsystem, while `once` records the
/// removal-before-invocation contract needed for re-entrant emits.
#[derive(Debug, Clone, PartialEq, Eq)]
struct EventListenerRecord {
    listener: Value,
    once: bool,
}

/// Immutable callback identity plus mutable one-shot state for the callable
/// function exposed by `rawListeners()`. The public `.listener` property lives
/// on the wrapper's heap-backed property object and may be reassigned without
/// changing which callback the wrapper ultimately invokes, matching Node.
#[derive(Debug, Clone, PartialEq, Eq)]
struct EventOnceWrapperState {
    target: ObjectId,
    event: RuntimePropertyKey,
    original_listener: Value,
    fired: bool,
    /// `Some(waiter_id)` when this wrapper is the guest-visible carrier for a
    /// static `events.once` Promise registration (bd-asw4m.4) rather than a
    /// `emitter.once()` listener. Its settlement is driven by
    /// `settle_event_promise_waiters`, never by invoking the wrapper, so the
    /// emit dispatch loop skips it and the promise-waiter removal path drops it
    /// by matching `waiter_id`.
    static_once_waiter: Option<u64>,
}

/// One link in the Promise-backed static `events.once` waiter table
/// (bd-asw4m.1). Non-error waits install a Resolve link under the requested
/// event and a Reject link under `error`, sharing `waiter_id`; settling either
/// link removes both before queuing the Promise reaction.
#[derive(Debug, Clone, PartialEq, Eq)]
struct EventPromiseWaiterRecord {
    waiter_id: u64,
    promise: crate::promise_model::PromiseHandle,
    action: EventPromiseWaiterAction,
    registration_label: Label,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EventPromiseWaiterAction {
    Resolve,
    Reject,
}

/// The core interpreter loop shared between both lanes.
/// One register's value and IFC label as observed at a capture tick
/// (bd-fqlfw.3.5.5 / E3.T5d). Only registers holding a non-`Undefined`
/// value are recorded — a fresh register file is all-`Undefined` and
/// recording it would bury the signal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapturedRegisterState {
    pub register: u32,
    pub value: Value,
    pub label: Label,
}

/// One live heap object and its derived IFC label as observed at a capture
/// tick (bd-fqlfw.3.5.5 / E3.T5d). The engine's IFC model tracks labels at
/// REGISTER granularity, so a heap object's label here is the join of the
/// labels of every register from whose value the object is transitively
/// reachable (property values and prototype links), defaulting to `Public`
/// when unreachable from any register. This is a projection of the real
/// register-label state, not an independent model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapturedHeapState {
    pub object_id: ObjectId,
    pub object: HeapObject,
    pub label: Label,
}

/// Deterministic interpreter-state observation captured at a nondeterminism
/// tick boundary for the time-travel debugger (bd-fqlfw.3.5.5 / E3.T5d).
/// Identical module + config + requested tick yields an identical
/// observation, because execution itself is deterministic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedInterpreterState {
    /// The nondeterminism tick (trace event count) the capture landed on.
    pub tick: u64,
    pub registers: Vec<CapturedRegisterState>,
    pub heap: Vec<CapturedHeapState>,
    pub(crate) symbol_state: RuntimeSymbolState,
}

impl CapturedInterpreterState {
    fn contains_symbol_values(&self) -> bool {
        self.registers
            .iter()
            .any(|entry| value_contains_symbol(&entry.value))
            || self
                .heap
                .iter()
                .any(|entry| heap_object_contains_symbols(&entry.object))
    }
}

impl Serialize for CapturedInterpreterState {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct as _;

        let include_symbol_state = !self.symbol_state.is_default() || self.contains_symbol_values();
        let mut state = serializer.serialize_struct(
            "CapturedInterpreterState",
            if include_symbol_state { 4 } else { 3 },
        )?;
        state.serialize_field("tick", &self.tick)?;
        state.serialize_field("registers", &self.registers)?;
        state.serialize_field("heap", &self.heap)?;
        if include_symbol_state {
            state.serialize_field("symbol_state", &self.symbol_state)?;
        }
        state.end()
    }
}

impl<'de> Deserialize<'de> for CapturedInterpreterState {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;

        #[derive(Deserialize)]
        struct CapturedInterpreterStateWire {
            tick: u64,
            registers: Vec<CapturedRegisterState>,
            heap: Vec<CapturedHeapState>,
            #[serde(default, deserialize_with = "deserialize_present_value")]
            symbol_state: Option<PresentValue<RuntimeSymbolState>>,
        }

        let wire = CapturedInterpreterStateWire::deserialize(deserializer)?;
        let symbol_state_was_present = wire.symbol_state.is_some();
        let state = Self {
            tick: wire.tick,
            registers: wire.registers,
            heap: wire.heap,
            symbol_state: wire.symbol_state.map(|state| state.0).unwrap_or_default(),
        };
        if !symbol_state_was_present && state.contains_symbol_values() {
            return Err(D::Error::custom(
                "captured state with Symbol values or keys requires symbol_state",
            ));
        }
        state.symbol_state.validate().map_err(D::Error::custom)?;
        for entry in &state.registers {
            validate_symbol_value(&state.symbol_state, &entry.value).map_err(D::Error::custom)?;
        }
        for entry in &state.heap {
            validate_heap_symbol_references(&state.symbol_state, &entry.object)
                .map_err(D::Error::custom)?;
        }
        Ok(state)
    }
}

pub struct InterpreterCore {
    config: InterpreterConfig,
    hook: Option<Arc<dyn InterpreterHook>>,
    /// Precomputed capability-pruned hostcall dispatch metadata (E9.T4,
    /// bd-fqlfw.9.4). `None` = live classification on every call; installed
    /// only by the E9 activation gate after receipt/epoch/replay approval.
    pruned_hostcall_dispatch: Option<PrunedHostcallDispatch>,
    /// The grant each running generated-code activation replaced, outermost
    /// first: the program's own grant comes back for a program closure that
    /// generated code calls (bd-9vouw.189).
    codegen_caller_grants: Vec<BTreeSet<RuntimeCapability>>,
    /// True only while `prepare_execution` runs engine-internal setup
    /// (module-namespace record, runtime globals). Containment hooks are
    /// suppressed during this window: no extension instruction has executed
    /// yet, so there is nothing for a policy to attribute (bd-gug3l).
    preparing_execution: bool,
    /// Nondeterminism tick at which to capture a deterministic
    /// interpreter-state observation for the time-travel debugger
    /// (bd-fqlfw.3.5.5 / E3.T5d). Checked at instruction boundaries; the
    /// capture fires when the trace's event count first reaches the
    /// requested tick, and only an exact count match produces a snapshot
    /// (fail-closed when a single instruction emitted several events and
    /// no boundary landed on the tick). `None` disarms the check entirely.
    state_capture_tick: Option<u64>,
    /// The observation produced by the armed capture, taken via
    /// [`InterpreterCore::take_captured_state`].
    state_capture_result: Option<CapturedInterpreterState>,
    /// Optional sandboxed host-I/O provider (bd-f5b04.2.7). When set, authorized
    /// `fs:` hostcalls dispatch to real host effects through the algebraic-effects
    /// handler stack instead of returning `undefined`. `None` preserves the
    /// fail-closed baseline (no real host I/O).
    host_io: Option<Arc<dyn HostIoProvider>>,
    /// Optional deterministic-replay recorder paired with `host_io`; captures each
    /// dispatched effect as a `(request, outcome)` transcript entry.
    host_io_recorder: Option<Arc<dyn HostIoRecorder>>,
    /// Extraordinary process provider installed only after product-level signed
    /// admission. The shared journal retains exact inter-family crossing order.
    process_spawn: Option<Arc<dyn ProcessSpawnProvider>>,
    host_effect_journal: Option<Arc<InMemoryHostEffectJournal>>,
    /// Optional product cell authority for timer effects. The deterministic
    /// timer registry and event loop remain owned by this interpreter; the
    /// authority gates and records the crossing before mutation.
    timer_effect_authority: Option<Arc<dyn TimerEffectAuthority>>,
    /// The flow label ceiling of the entry module's lowering, when the
    /// embedder lowered it (bd-j8f7q): an import edge back to the entry
    /// (a cycle through it) is checked against it like any other module's.
    entry_flow_label_ceiling: Option<Label>,
    /// Register file (flat, indexed by register number). SEED-SURFACE.
    registers: SeedTrackedField<Vec<Value>>,
    /// [`Self::registers_memory_bytes`] of the register file as it stands, or
    /// `None` once a write may have changed it. An isolated callback reads
    /// the sum for its preflight, its snapshot, its setup and its restore;
    /// each read walked the whole file (grown with the call depth), about a
    /// tenth of babel-standalone's run time. Every register write clears it
    /// in [`Self::mutate_registers`]; installing a whole file sets it.
    registers_value_bytes: std::cell::Cell<Option<u64>>,
    /// Cached [`Self::register_labels_memory_bytes`], `None` when stale
    /// (bd-9vouw.376). Every isolated callback's snapshot and restore read it,
    /// and each read summed the whole label file (`max_registers` slots):
    /// 8% of a forEach loop. A label write whose bytes the writer knows moves
    /// it by that delta ([`Self::adjust_register_labels_bytes`]); a write of
    /// two byte-free labels leaves it; any other change of the file clears it.
    register_labels_bytes: std::cell::Cell<Option<u64>>,
    /// Each tagged-template call site's frozen template object, keyed by its
    /// module's content hash (else label) and parse ordinal (ES2020
    /// 12.2.9.3 [[TemplateMap]], bd-9vouw.343). Collector roots.
    template_objects: BTreeMap<(String, String), ObjectId>,
    /// Call stack.
    call_stack: CallStack,
    /// Object heap. SEED-SURFACE.
    heap: SeedTrackedField<Heap>,
    /// Approximate live non-seed memory tracked for fail-closed budget enforcement.
    /// Live execution-seed reservations are held separately in
    /// `execution_seed_reservation_ledger` and joined at every admission gate.
    estimated_memory_bytes: u64,
    /// Stack-local register carriers owned by the two legacy synchronous
    /// callback interpreters. Keeping this separate from retained base memory
    /// makes every nested allocation gate see the temporary owner while still
    /// allowing exact release on every callback exit (bd-aw8td).
    simple_callback_temporary_bytes: u64,
    /// The reducer lane's register file between callbacks, every slot
    /// `Undefined`, so a callback neither allocates nor drops `max_registers`
    /// slots. Engine capacity of at most `max_registers` slots, not charged.
    simple_callback_register_pool: Vec<Value>,
    /// The register and label files `take_generator_execution` emptied, every
    /// slot undefined with a Public label, which the next
    /// `install_generator_execution` or `isolate_module_execution` refills
    /// instead of allocating and clearing whole windows: an `await` or a
    /// generator step moved four windows through the allocator
    /// (bd-9vouw.500). Engine capacity of at most `SPARE_REGISTER_FILES`
    /// pairs of at most `SPARE_REGISTER_FILE_WINDOWS` windows a file, not
    /// charged.
    spare_register_files: Vec<(Vec<Value>, Vec<Label>)>,
    /// The bytes of the last found-property witness event, kept so a
    /// property read folds its event without allocating a buffer. Engine
    /// capacity (at most PROPERTY_WITNESS_SCRATCH_MAX_CAPACITY bytes kept),
    /// not charged.
    property_witness_scratch: Vec<u8>,
    /// The argument values and labels of the call being set up, kept so a
    /// call does not allocate and free two vectors (bd-9vouw.497). Empty
    /// between calls: a call takes them, drains them into the callee's
    /// registers and puts them back (`restore_call_argument_scratch`); a call
    /// that fails in between drops them. Engine capacity (at most
    /// CALL_ARGUMENT_SCRATCH_MAX_CAPACITY slots each kept), not charged.
    call_argument_value_scratch: Vec<Value>,
    call_argument_label_scratch: Vec<Label>,
    /// JSON parser/reviver scratch retained on the Rust stack across guest
    /// callbacks. A nested accounting resync must not erase this ownership.
    json_parse_temporary_bytes: u64,
    /// Owned RegExp input/output carriers live across native and guest calls.
    /// Their RAII reservations survive nested accounting resynchronization.
    regexp_temporary_bytes: Rc<Cell<u64>>,
    /// Resident ownership held by nested module/callback snapshots while the
    /// corresponding active core fields are temporarily replaced.
    module_snapshot_in_flight_bytes: u64,
    /// Active caller execution moved to a stack-local owner while a generator
    /// activation is installed. It remains logically resident and therefore
    /// charged until the caller context is restored.
    temporarily_suspended_execution_bytes: u64,
    /// Dedicated iterator runtime state used by iterator-specific IR3 ops.
    iterators: ReclaimableTable<RuntimeIteratorState>,
    /// The live Map/Set iterators (handles into `iterators`) of each
    /// collection storage object, which `collection_delete` and
    /// `collection_clear` move back (bd-9vouw.131). An exhausted iterator
    /// leaves; a reclaimed or finished handle is pruned on the next visit.
    collection_iterators: BTreeMap<ObjectId, BTreeSet<u32>>,
    /// The (storage, next position) cursors of the Map/Set forEach calls in
    /// progress, innermost last, moved back like `collection_iterators`
    /// (bd-9vouw.131).
    collection_for_each_cursors: Vec<(ObjectId, usize)>,
    /// Replay-visible iterator protocol traces keyed by runtime iterator state.
    iteration_traces: Vec<IterationTrace>,
    /// Lazily allocated prototype objects for constructor functions, keyed by
    /// immutable owner-module identity plus the module-local function index.
    /// SEED-SURFACE.
    function_prototypes: SeedTrackedField<BTreeMap<(ContentHash, u32), ObjectId>>,
    /// Owner ids already digested, by module header (bd-9vouw.124).
    prototype_owner_ids: std::cell::RefCell<Vec<(IrHeader, PrototypeOwnerIds)>>,
    /// Per-function "uses the lexical super" answers, by module header
    /// (bd-9vouw.159).
    lexical_super_functions: std::cell::RefCell<Vec<(IrHeader, std::sync::Arc<Vec<bool>>)>>,
    /// Set once a built-in function may have a backing object in
    /// `function_prototypes`; never cleared. Until then a property read on a
    /// built-in skips the identity digest (a JSON encoding and two SHA-256
    /// hashes) that locates one (bd-9vouw.17).
    builtin_function_backings: bool,
    /// Set once `delete` removed a virtual own property of a canonical
    /// prototype ([`HeapObject::deleted_virtual_keys`]); never cleared.
    /// Until then the virtual lookups skip the tombstone check
    /// (bd-9vouw.93).
    virtual_property_deletions: bool,
    /// Lazily allocated prototype objects for modeled builtin constructors. SEED-SURFACE.
    builtin_prototypes: SeedTrackedField<BTreeMap<String, ObjectId>>,
    /// Current seed epoch for lazy materialization.
    seed_epoch: u64,
    /// Pending lazy seeds to materialize on next write.
    pending_lazy_seeds: Vec<std::rc::Weak<ExecutionSeedShared>>,
    /// `arguments` object staged by call setup for the callee's entry marker
    /// (bd-9vouw.25): (call-stack depth of the callee frame, object, label).
    pending_arguments_object: Option<(usize, Value, Label)>,
    /// Private [[ParameterMap]] of sloppy simple-parameter arguments objects.
    /// Indexed properties mirror these cells; aliases never expose accessors.
    mapped_argument_bindings: BTreeMap<ObjectId, BTreeMap<u32, ScopeBinding>>,
    /// Weak reverse index: a live parameter alone does not root its arguments.
    mapped_argument_aliases: BTreeMap<usize, (ObjectId, u32)>,
    /// Out-of-band argument lists of the active synthetic call sites, one
    /// entry per site (empty when its list fits the frame), innermost last
    /// (bd-9vouw.50). Only the last is readable; every entry is a GC root.
    argument_overflow: Vec<ArgumentOverflow>,
    /// Charge for every entry of `argument_overflow`.
    argument_overflow_bytes: u64,
    /// Drop-aware ownership charged for every live execution-seed snapshot.
    execution_seed_reservation_ledger: std::rc::Rc<ExecutionSeedReservationLedger>,
    /// Current instruction pointer.
    ip: usize,
    /// Instructions executed counter.
    instructions_executed: u64,
    /// Holes visited by native element reads (`array_index_value`), which
    /// count against the instruction budget with `instructions_executed`
    /// (bd-9vouw.112). Builtins loop natively over an array-like's
    /// guest-chosen length (`indexOf.call({ length: 2 ** 40 })`). Present
    /// elements are bounded by the memory budget that holds them; holes are
    /// bounded by nothing else. Kept apart from `instructions_executed` so
    /// reported instruction counts do not change. A `Cell`, as the reads are
    /// `&self`.
    native_hole_reads: Cell<u64>,
    /// Source instructions handled by the compact Tier-I dispatch in the
    /// current execution.
    tier_i_instructions_executed: u64,
    tier_i_specialized_instructions_executed: u64,
    /// Witness events.
    witness_events: Vec<WitnessEvent>,
    /// Ordered timer callback commitment (count, SHA-256), sealed into one
    /// witness event at result handoff instead of retaining a row per tick
    /// (bd-9vouw.76). Contains no guest references or dynamic allocation.
    timer_callback_witness: Option<(u64, ContentHash)>,
    /// Ordered commitment to successful guest microtask enqueues. This keeps
    /// queueMicrotask's IR4 records bounded while every enqueue still checks
    /// live Timer authority and every denial remains individually recorded.
    microtask_enqueue_witness: Option<(u64, ContentHash)>,
    /// Hostcall decisions.
    hostcall_decisions: Vec<HostcallDecisionRecord>,
    /// Effect-free hostcall grants counted instead of recorded
    /// (bd-9vouw.83); see `check_hostcall_capability_gate`.
    folded_hostcall_decisions: u64,
    /// Effect-free hostcall tags whose last recorded decision is a grant.
    recorded_effect_free_grants: BTreeSet<String>,
    /// Recently compiled RegExp patterns by (pattern, flags), oldest first.
    /// Owned by this interpreter so no other execution can observe it.
    regexp_cache: RefCell<VecDeque<(String, String, CompiledRegExp)>>,
    /// Mandatory runtime security observability surface. The runtime capability
    /// gate feeds real `record_capability_denial` calls here so the
    /// `capability_denial_total` counter and structured security log reflect
    /// actual denials on the live execution path (not just a schema surface).
    security_observability: RuntimeSecurityObservability,
    /// Live hostcall telemetry recorder driven from every `dispatch_*_hostcall`
    /// path (bd-qi3hs). The deterministic timestamp source is the interpreter's
    /// own instruction counter, so the record sequence is byte-identical across
    /// replays. Recording is best-effort: backpressure (`ChannelFull`) never
    /// blocks JS execution, but every refusal increments completeness evidence.
    /// The recorder is exposed via [`InterpreterCore::hostcall_telemetry`] and
    /// copied into incident traces via
    /// [`crate::forensic_replayer::IncidentTrace::with_telemetry_recorder`].
    telemetry_recorder: TelemetryRecorder,
    /// Structured events.
    events: Vec<InterpreterEvent>,
    /// Exact logical ownership charged for the general (non-generated-code)
    /// structured events in `events` (bd-zaeeh). Generated-code events are
    /// charged separately via [`Self::generated_code_observability_bytes`], so
    /// this field deliberately excludes them to avoid double-charging.
    /// Eagerly maintained by [`Self::push_event`] and released when `events`
    /// is drained into [`ExecutionResult`], keeping general observability
    /// inside `max_total_memory_bytes` even when a core is reused across
    /// repeated failing executions (which retain the event vector).
    general_event_bytes: u64,
    /// Count of general structured events dropped because retaining them would
    /// have pushed the estimate past `max_total_memory_bytes` (bd-zaeeh).
    /// Deterministic containment evidence: a bounded diagnostic surface never
    /// silently exceeds the budget.
    dropped_event_count: u64,
    /// Append-only audit trail for `Function`-constructor-generated code
    /// (bd-8enww.3.4). Like `events`, this is observability that survives the
    /// re-entrant snapshot/restore of a generated-function call and is drained
    /// into [`ExecutionResult`] at the end of execution. Bounded by
    /// [`MAX_GENERATED_CODE_AUDIT_ENTRIES`] and charged together with its
    /// mirrored structured event, so adversarial construction/invocation
    /// cannot accumulate either surface outside `max_total_memory_bytes`.
    generated_code_audit: Vec<GeneratedCodeAuditEntry>,
    /// Exact logical ownership charged for generated-code audit entries and
    /// their paired standard structured events. General interpreter events are
    /// deliberately excluded so a future general-event budget can account for
    /// them without double-charging these generated-code pairs.
    generated_code_observability_bytes: u64,
    /// Pending worst-case audit/event ownership reserved across a generated
    /// function invocation. This is explicit state (rather than a raw addition
    /// to `estimated_memory_bytes`) so generator/async paths that perform an
    /// eager recomputation cannot erase the reservation while guest code runs.
    generated_code_observability_reservation_bytes: u64,
    /// Witness sequence counter.
    witness_seq: u64,
    /// Trace ID for logging.
    trace_id: String,
    /// Base register offset for current frame.
    register_base: usize,
    /// Width of the current frame's register window (bd-9vouw.72): the next
    /// callee's window starts at `register_base + register_width`. It never
    /// understates the registers the current frame can address: a verified
    /// frame width, or `max_registers` wherever the exact width is unknown.
    register_width: usize,
    /// Run loops currently active on the native stack (bd-9vouw.72).
    native_run_loop_depth: usize,
    /// Every register at or past this physical index holds `Undefined` with
    /// a Public label (bd-9vouw.499). A frame entry clears its window and
    /// every register up to here, then sets it to its window's end; every
    /// write past it (a register write, a label write, a restored or widened
    /// window, an installed file) raises it. It replaced a monotonic
    /// high-water mark of the widest frame ever entered, which every later
    /// entry cleared: after one call of a function with 200 registers, each
    /// call of a 3-register function cleared 200 values and labels (1,000,000
    /// calls took 4.60 s instead of 1.61 s).
    register_dirty_end: usize,
    /// The top-level run's compact Tier-I plan and the address of the module
    /// it was compiled for. Nested builtin callbacks in that same module
    /// dispatch through it too (verified frame widths, scope-inert leaves,
    /// compact opcodes) instead of the full-width baseline path.
    top_level_compact_tier1: Option<(usize, CompactTier1Program)>,
    /// Verified frame widths (`frame_size` per function) of the module the
    /// running `execute` call was given, with that module's address
    /// (bd-9vouw.72). A callee window of that module is its function's
    /// verified width whether or not a compact plan runs, so a plain
    /// `execute` recurses as deep as the planned path. Held for the whole
    /// call, event loop included, and restored on return; frames of any
    /// other module (a required module, a generated function) keep
    /// `max_registers` windows.
    entry_frame_widths: Option<(usize, Arc<[u32]>)>,
    /// Stack of active try/catch frames for exception unwinding.
    catch_frames: Vec<CatchFrame>,
    /// A pending exception value during an unwind edge, consumed by
    /// `EnterCatch` or moved into an owned `FinallyFrame` by `EnterFinally`.
    pending_exception: Option<Value>,
    /// IFC label shadowing `pending_exception` (bd-l0d6z, fifth member of the
    /// bd-n2mjy/bd-0zybl under-tainting family): set wherever a thrown value
    /// becomes pending, consumed by `EnterCatch` so the catch binding inherits
    /// the thrown value's label. Meaningful only while `pending_exception` is
    /// `Some`; reset to `Public` when the exception is cleared.
    pending_exception_label: Label,
    /// Out-of-band IFC label returned by builtin hostcalls whose implementation
    /// invokes a user callable in an isolated module wrapper. The enclosing
    /// `HostCall` consumes this exactly once and joins it with the ordinary
    /// argument label before writing the destination register.
    pending_hostcall_result_label: Option<Label>,
    /// bd-9vouw.113: the realm's last successful RegExp match, which the
    /// legacy statics (`RegExp.$1`, `lastMatch`, ...) read.
    legacy_regexp_match: Option<LegacyRegExpMatch>,
    /// Bumped on every recorded match, so a builtin call can tell whether it
    /// recorded one.
    legacy_regexp_generation: u64,
    /// The label of the legacy statics read by the current GetProperty.
    legacy_regexp_read_label: Option<Label>,
    /// A pending return value and IFC label before `EnterFinally` captures it
    /// or the return completes.
    pending_return: Option<LabeledReturn>,
    /// Saved outer abrupt completion state that was temporarily suspended by a
    /// newer local throw/return or by exception unwinding across nested calls
    /// or intermediary finally blocks. If the newer abrupt completion is
    /// consumed locally, the most recent suspended completion resumes.
    suspended_abrupt_completions: Vec<AbruptCompletion>,
    /// Stack of completion records owned by active finally bodies. Pushed by
    /// `EnterFinally` and consumed by `EndFinally` or an overriding abrupt
    /// transfer.
    finally_frames: Vec<FinallyFrame>,
    /// One-shot entry ownership set by an unwind edge and consumed by the
    /// exact `EnterFinally` instruction it targets.
    pending_finally_entry: Option<PendingFinallyEntry>,
    /// Pre-run caller-visible seed used for the most recent execute().
    last_pre_run_seed: Option<ExecutionSeedHandle>,
    /// Seed epoch immediately after the most recent execute(). Every seed-surface
    /// write clears this marker before advancing the epoch, preventing wraparound ABA.
    last_post_run_epoch: Option<u64>,
    /// Runtime scope chain for lexical variable resolution.
    scope_chain: ScopeChain,
    /// Realm-owned bindings created by sloppy writes to unresolvable names.
    ///
    /// This map is deliberately outside closure, generator, generated-code,
    /// and module execution snapshots: those mechanisms replace the active
    /// lexical scope structure, but they all share one realm global
    /// environment for the duration of one top-level realm. Realm rotation
    /// clears the map before seed-backed heap ObjectIds can be reused.
    realm_dynamic_globals: BTreeMap<String, ScopeBinding>,
    /// The realm's global object (`globalThis`, bd-9vouw.17): seeded once per
    /// realm and bound in every module's scope chain. A free identifier that
    /// no binding resolves reads and writes its properties, own or inherited,
    /// as a global environment's object record does. Cleared with the realm.
    realm_global_object: Option<ObjectId>,
    /// The authority-bearing process object stays outside the public global
    /// object and is shared by module scopes. This root also lets the private
    /// util argv reader ignore guest bindings named `process`.
    process_global_object: Option<ObjectId>,
    /// Engine-owned sanitized outer environment for `Function`-constructor
    /// artifacts. Binding cells persist for one top-level realm, while every
    /// invocation receives fresh frame structure that shares only these
    /// canonical cells. Caller/owner module bindings remain disconnected.
    generated_function_realm_globals: Option<BTreeMap<String, ScopeBinding>>,
    /// Monotonic realm identity mixed into every generated-artifact id.
    /// Module snapshots deliberately do not restore this process-lifetime
    /// nonce; top-level realm replacement advances it and invalidates every
    /// older generated handle fail closed.
    generated_function_realm_generation: u64,
    /// Exact pre-RHS identifier References indexed by opaque integer tokens in
    /// internal status registers. Entries are identity-deduplicated, so loops
    /// do not grow this table once they keep resolving to the same cell.
    runtime_name_references: Vec<RuntimeNameReference>,
    /// Closure store: maps closure IDs to captured environments, with the
    /// running accounting totals for them and for suspended activations.
    closures: ClosureTable,
    /// Non-forgeable concise-method identity and [[HomeObject]], keyed by the
    /// closure occurrence produced while evaluating the object literal.
    closure_method_metadata: ClosureSideTable<ClosureMethodMetadata>,
    /// Non-forgeable lexical `super` binding captured by closures created in a
    /// concise-method frame. Parser context prevents ordinary nested functions
    /// from containing `super`; this private carrier serves the nested-arrow
    /// lane without exposing a guest-writable marker.
    closure_lexical_super_metadata: ClosureSideTable<ClosureLexicalSuperMetadata>,
    /// Lexical `this` captured at `CreateArrowClosure` /
    /// `CreateAsyncArrowClosure` (bd-asw4m.3): closure_id -> the creating
    /// frame's `this` value and label. Consulted by
    /// `clone_closure_lexical_this_binding` so every `Call`/`CallMethod`
    /// binds the arrow's defining `this` instead of the receiver or the
    /// caller's live `this`. Ordinary closures have no entry.
    arrow_lexical_this: ClosureSideTable<(Value, Label)>,
    /// Program provenance for closures created by the live interpreter. Test
    /// fixtures that seed the private closure table directly intentionally
    /// have no entry and retain same-module behavior.
    closure_module_origins: ClosureSideTable<String>,
    /// Generated-artifact program provenance for closures whose function
    /// indices belong to a retained `Function` constructor artifact rather
    /// than to `closure_module_origins`' ordinary module program.
    closure_generated_function_artifacts: ClosureSideTable<GeneratedFunctionArtifactHandle>,
    /// Cross-module calls execute through an isolated wrapper whose local call
    /// stack is intentionally empty. Keep an outer, non-snapshotted depth so
    /// alternating module recursion cannot reset `max_call_depth` at every
    /// boundary and recurse through Rust frames without containment.
    module_reentrant_call_depth: usize,
    /// Non-zero only while an imported ordinary closure is executing in its
    /// retained owner program.
    active_foreign_module_call_depth: usize,
    /// bd-9vouw.26: every async-function call runs in an isolated wrapper
    /// activation so a pending `await` parks only that activation and the
    /// caller continues with the result Promise. Set just before the wrapper
    /// runs and consumed by the wrapper's own entry call, which must execute
    /// inline instead of isolating again.
    isolated_async_entry_pending: bool,
    /// Set by a call site that may let the collector run inside the inline
    /// call it is about to make (bd-9vouw.77): the values its Rust frames hold
    /// across that call. The next `invoke_inline_method_call_*` consumes it.
    gc_nested_request: Option<Vec<Value>>,
    /// A function `this` an Array.prototype method runs on generically
    /// (bd-9vouw.285): its own-property object and the function, which is
    /// what the algorithm's O is wherever it is observable (a callback's
    /// third argument, a getter's receiver, a returned O).
    generic_function_receiver: Option<(ObjectId, Value)>,
    /// Pending capture names for the next `CreateClosure` instruction.
    pending_captures: Vec<u32>,
    /// Generator object store.
    generators: ReclaimableTable<GeneratorObject>,
    /// bd-hoplz: set by the `Yield` instruction handler so `generator_next` can
    /// distinguish a yield-suspension (`run_loop` exits `Ok(yield_obj)`) from a
    /// completion-by-return (`run_loop` also exits `Ok(return_val)` when the
    /// generator body runs off the end or hits `Return`). Reset to `false`
    /// before each `run_loop` resume and consumed immediately after.
    generator_yielded: bool,
    /// Destination register associated with the most recent generator yield.
    /// Cleared before every resume and consumed together with
    /// `generator_yielded`.
    generator_resume_dst: Option<u32>,
    /// IFC label of the value yielded by the most recent generator suspension.
    generator_result_label: Label,
    /// bd-9vouw.49: the generator a call is starting through its parameter
    /// prologue; `generator_resume_with_async` takes it for that one run.
    generator_prologue_pending: Option<u32>,
    /// bd-9vouw.49: whether the running generator activation suspends at its
    /// `generator:prologue` marker (set only for the run a call started;
    /// saved and restored around nested generator resumptions).
    suspend_at_generator_prologue: bool,
    /// Execution-local delegation, transferred with the complete activation
    /// when a nested generator or isolated async continuation runs.
    generator_delegation: Option<GeneratorDelegation>,
    /// Async function object store.
    async_functions: ReclaimableTable<AsyncFunctionObject>,
    /// Context information for async function resumption after await.
    async_resumption_contexts: BTreeMap<u32, AsyncResumptionContext>,
    /// Promise-reaction contexts for pending entry-module top-level awaits.
    /// Keyed by the Promise returned from the internal `.then()` registration,
    /// matching `async_resumption_contexts`.
    top_level_await_resumption_contexts: BTreeMap<u32, TopLevelAwaitResumptionContext>,
    /// Completion produced when a resumed entry module either falls through,
    /// halts, or throws. `drain_microtasks` cannot return an error directly, so
    /// the outer execution driver consumes this after the event-loop drain.
    top_level_await_outcome: Option<Result<LabeledReturn, InterpreterError>>,
    /// Async generator object store. The collector reclaims entries nothing
    /// names (bd-9vouw.57).
    async_generators: ReclaimableTable<AsyncGeneratorObject>,
    /// FIFO request continuations use the existing Promise reaction queue.
    async_generator_runtime: AsyncGeneratorRuntime,
    /// Promise store for ES2020 Promise semantics.
    promise_store: crate::promise_model::PromiseStore,
    /// Deterministic event loop state (microtasks + macrotasks + virtual clock).
    event_loop: crate::promise_model::EventLoop,
    /// Queue ownership moved to a stack-local Promise/macrotask action remains
    /// physically live until that action returns. Keep the queue's released
    /// component charged during the transfer so nested Promise mutations see
    /// one coherent runtime component.
    promise_in_flight_task_bytes: u64,
    /// Non-closure callable Promise reaction handlers (builtin functions such
    /// as `console.log`, async/generator function objects) registered through
    /// `.then`/`.catch`/`.finally`. Keyed by a synthetic id at or above
    /// [`PROMISE_REACTION_CALLABLE_BASE`] so the microtask queue's
    /// `ClosureHandle` transport stays unchanged while the id can never
    /// collide with a real closure-table index (bd-sxh8o.1).
    promise_reaction_callables: BTreeMap<u32, Value>,
    /// Values `JsValue` cannot express, keyed by carrier id (bd-9vouw.69).
    /// An entry lives while a traced promise value, queued job or combinator
    /// names its id; the collector purges the rest.
    promise_value_carriers: BTreeMap<u32, Value>,
    next_promise_value_carrier: u32,
    /// Node-compatible `process.nextTick` job queue (bd-8nrud). Drained
    /// completely before each Promise microtask at every checkpoint, matching
    /// Node's next-tick-before-Promise ordering. Populated only by the
    /// statically recognized `builtin:ProcessNextTick` hostcall — the raw
    /// `process` object is never exposed.
    next_tick_queue: std::collections::VecDeque<NextTickTask>,
    /// Next unused synthetic id for `promise_reaction_callables`.
    next_promise_reaction_callable_id: u32,
    /// Whether the most recent builtin dispatch fell through to the
    /// unknown-member arm (bd-z1peg.3). The `builtin:` registry row is a
    /// family wildcard whose direct dispatch deterministically yields
    /// `undefined` for unknown members; the DELEGATED path must instead fail
    /// closed, so it consumes this flag to convert that silent fallthrough
    /// into a CapabilityDenied. A plain `bool`, so it carries no memory
    /// accounting weight.
    builtin_dispatch_hit_unknown_member: bool,
    /// bd-201vt: pending arguments for scheduled async fs callbacks
    /// (`fs.readFile`/`fs.writeFile` callback forms), keyed by the `IoCompletion`
    /// macrotask's registration sequence. The host effect runs synchronously at
    /// dispatch; the callback's `(err[, data])` arguments are stashed here and the
    /// callback is deferred to the next event-loop turn. `execute_macrotask_callback`
    /// drains the entry by seq when it fires, so the map never retains completed
    /// callbacks.
    pending_io_callbacks: BTreeMap<u64, Vec<Value>>,
    /// Native fs/promises read completions, keyed by the I/O registration.
    /// Entries stay rooted and charged while their Promise adopts a value.
    pending_fs_promise_reads: BTreeMap<u64, Arc<PendingFsPromiseRead>>,
    /// Deferred import() host jobs, keyed by the scheduler registration.
    /// Entries remain present during evaluation to root their owned handles.
    pending_dynamic_imports: BTreeMap<u64, Arc<PendingDynamicImportTask>>,
    /// Arguments transferred out of the deferred I/O callback queue remain
    /// owned by the invocation while guest code runs. Keep their charge in
    /// the memory oracle while nested collections are enabled.
    deferred_callback_in_flight_bytes: u64,
    /// Lifecycle process waits scheduled after the guest receives its
    /// `ChildProcess` facade. The provider `Spawn` crossing happens on the
    /// initiating stack; `Wait` runs on the deterministic I/O lane so listener
    /// registration and optional callbacks observe Node-style async ordering.
    pending_child_process_tasks: BTreeMap<u64, PendingChildProcessTask>,
    /// Ownership transferred out of `pending_child_process_tasks` remains
    /// physically live during the provider Wait and terminal event scheduling.
    /// Keep it charged so nested work sees exact memory pressure.
    child_process_task_in_flight_bytes: u64,
    /// Registered listeners shared by standalone `EventEmitter` objects and the
    /// HTTP stream objects (`ClientRequest` / `IncomingMessage`), keyed by heap
    /// object id then exact string/Symbol event name. No string encoding can
    /// alias a symbol identity (bd-9vouw.307). Records stay in registration order and carry
    /// `once` state; holding them outside the heap keeps listeners live across
    /// deferred HTTP event-loop turns (bd-3894s, bd-2dmnn).
    event_listeners: BTreeMap<ObjectId, BTreeMap<RuntimePropertyKey, Vec<EventListenerRecord>>>,
    /// Private state for stable callable `once` wrappers, keyed by the same
    /// heap object that backs each wrapper's public `.listener` property.
    /// Execution-local state is cleared before a restored heap can reuse an
    /// ObjectId (bd-asw4m.2).
    event_once_wrappers: BTreeMap<ObjectId, EventOnceWrapperState>,
    /// Promise-backed static `events.once` waiters. Linked Resolve/Reject
    /// records share a waiter id so settling either event removes every sibling
    /// link before its Promise reaction becomes observable (bd-asw4m.1).
    event_promise_waiters:
        BTreeMap<ObjectId, BTreeMap<RuntimePropertyKey, Vec<EventPromiseWaiterRecord>>>,
    next_event_promise_waiter_id: u64,
    /// Authenticated child-process facades whose native lifecycle has settled
    /// under provider limits. Pending facades move here on their deterministic
    /// I/O `Wait` turn; listener registration then exposes only engine-owned
    /// bounded results without trusting guest tags.
    completed_child_processes: BTreeMap<ObjectId, CompletedChildProcessState>,
    child_process_streams: BTreeMap<ObjectId, (ObjectId, ChildProcessStreamKind)>,
    /// Provider-scoped opaque handles for live lifecycle children (bd-m42c2),
    /// keyed by the `ChildProcess` facade object. Entries are charged at
    /// spawn success and released when the facade's lifecycle state is
    /// removed, so post-settle `kill`/`stdin.write` fail closed like Node.
    child_process_handles: BTreeMap<ObjectId, String>,
    /// Non-forgeable WHATWG URL brands and state (bd-8y0gs). These maps are
    /// execution-local and are cleared before a seed can reuse heap ObjectIds.
    url_objects: BTreeMap<ObjectId, UrlRuntimeState>,
    url_search_params: BTreeMap<ObjectId, UrlSearchParamsRuntimeState>,
    /// One authenticated facade/settings pair per execution. Repeated bare or
    /// `node:` cluster hostcalls return this same facade identity.
    cluster_facades: BTreeMap<ObjectId, ClusterRuntimeState>,
    /// Non-forgeable hash/HMAC/cipher state keyed by the JS-visible object's
    /// heap identity. Guest `__type` fields are never consulted (bd-2z157).
    crypto_objects: BTreeMap<ObjectId, CryptoObjectState>,
    stream_pipelines: BTreeMap<u32, StreamPipelineState>,
    next_stream_pipeline_token: u32,
    /// bd-3894s slice (2d): deferred readable-stream emissions (`'data'`/`'end'`),
    /// keyed by the `IoCompletion` macrotask registration sequence (parallel to
    /// `pending_io_callbacks`, which carries closure callbacks). Drained by
    /// `execute_macrotask_callback` when the macrotask fires. Each entry carries
    /// the ordinary conservative map-entry charge.
    pending_stream_emissions: BTreeMap<u64, PendingStreamEmission>,
    /// Finite `Readable.from` streams keyed by their JS-visible heap object.
    /// Values and IFC labels remain engine-owned while lifecycle events reuse
    /// the shared EventEmitter tables above.
    readable_from_streams: BTreeMap<ObjectId, ReadableFromState>,
    /// Released Readable instances retain compact IFC provenance without
    /// participating in live pump scans.
    readable_terminal_states: BTreeMap<ObjectId, ReadableTerminalState>,
    /// Scheduled pure-compute stream pumps keyed by their `IoCompletion`
    /// registration sequence. At most one pump is queued per readable object;
    /// each entry carries the ordinary conservative map-entry charge.
    pending_readable_from_pumps: BTreeMap<u64, ObjectId>,
    /// Exact event-loop bytes precharged across a guest callback before its
    /// successor Readable pump receives a registration sequence. This keeps
    /// callback-created timers/I/O ahead of the successor pump without letting
    /// callback allocations consume the pump's already-promised headroom.
    /// The reservation's EventLoop headroom and its map entry are charged
    /// independently so conversion can transfer both without a gap.
    readable_pump_reservations: BTreeMap<ObjectId, ReadablePumpReservation>,
    /// Current `readable` listener receiver, saved/restored across nested
    /// synchronous emissions. This authenticates pull-drain observations
    /// without consulting a forgeable public flow mirror.
    active_readable_listener_target: Option<ObjectId>,
    /// At most one bounded pipe destination per live Readable. Internal
    /// listener builtins authenticate against this table before forwarding.
    readable_pipe_links: BTreeMap<ObjectId, ReadablePipeLink>,
    /// Reverse ownership edge. The bounded pipe subset permits one incoming
    /// Readable per Writable, making destination terminalization O(log N)
    /// instead of repeatedly scanning every source link.
    readable_pipe_sources: BTreeMap<ObjectId, ObjectId>,
    /// Process-lifetime nonce for pipe listeners. This is intentionally not
    /// reset when an execution seed restores heap ObjectIds.
    next_readable_pipe_token: u32,
    /// Hermetic same-interpreter `net` transport state (bd-7qwej). Listener
    /// ports are deterministic execution-local identifiers, never OS ports.
    loopback_servers: BTreeMap<ObjectId, LoopbackServerState>,
    loopback_sockets: BTreeMap<ObjectId, LoopbackSocketState>,
    loopback_ports: BTreeMap<u16, LoopbackPortState>,
    pending_loopback_tasks: BTreeMap<u64, PendingLoopbackTask>,
    loopback_task_in_flight_bytes: u64,
    next_loopback_port: u16,
    /// Process-lifetime listener nonce. It is intentionally not reset with an
    /// execution seed, so a delayed task can never authenticate against a
    /// newly reused heap ObjectId.
    next_loopback_listener_generation: u64,
    /// Bounded HTTP/1.1 facade state. All transport identities and payloads are
    /// engine-owned; guest `__type` writes cannot forge membership.
    http_servers: BTreeMap<ObjectId, HttpServerState>,
    http_client_requests: BTreeMap<ObjectId, HttpClientRequestState>,
    http_incoming_messages: BTreeMap<ObjectId, HttpIncomingMessageState>,
    http_server_responses: BTreeMap<ObjectId, HttpServerResponseState>,
    http_agents: BTreeSet<ObjectId>,
    pending_http_tasks: BTreeMap<u64, PendingHttpTask>,
    http_task_in_flight_bytes: u64,
    /// Engine-owned Writable instances. Their per-state ready bit drives a
    /// pre-microtask lifecycle checkpoint without a separately retained queue.
    writable_streams: BTreeMap<ObjectId, WritableState>,
    /// Released Writable instances retain a compact authoritative terminal
    /// record without participating in active-stream scheduler scans.
    writable_terminal_states: BTreeMap<ObjectId, WritableTerminalState>,
    /// Dynamic payload moved out of Writable queues but still physically live
    /// while a deferred guest callback runs. Nested callbacks add independent
    /// charges; each invocation releases only its own remainder on unwind.
    writable_in_flight_callback_bytes: u64,
    /// Number of terminal states whose post-close callback tick is armed. A
    /// zero value lets normal checkpoints skip the persistent tombstone map.
    pending_writable_terminal_ticks: usize,
    next_writable_tick_sequence: u64,
    /// Process-lifetime authentication nonce for internal Writable completion
    /// callbacks. Unlike heap ObjectIds and execution seeds, this counter is
    /// never reset between `execute()` calls, so a deferred callback retained
    /// by an unref'd timer cannot authenticate against a newly reused object.
    next_writable_completion_token: u32,
    /// Active promise combinator trackers keyed by combinator id.
    promise_combinators: BTreeMap<u64, PromiseCombinatorState>,
    /// Watchers keyed by promise handle for combinator updates.
    promise_combinator_watchers:
        BTreeMap<crate::promise_model::PromiseHandle, Vec<PromiseCombinatorWatcher>>,
    /// Running totals of the two maps' memory estimates
    /// (`promise_combinators_memory_bytes_by_walk` and
    /// `promise_combinator_watchers_memory_bytes_by_walk`), kept up to date at
    /// every mutation. Every Promise operation measures them, and re-summing
    /// made a pending Promise.all over n inputs cost O(n) per settlement and
    /// per registered input (bd-9vouw.479).
    promise_combinators_bytes: u64,
    promise_combinator_watchers_bytes: u64,
    /// Arrays an Array.prototype.join / toString is joining right now,
    /// across guest re-entry (bd-9vouw.481): one of them met again renders
    /// "". Empty between instructions.
    array_join_stack: BTreeSet<u32>,
    /// Monotonic combinator id generator.
    next_promise_combinator_id: u64,
    /// Module registry/cache for ImportModule execution.
    module_state: ModuleState,
    /// Trusted source delivery for this run; never an ambient-path fallback.
    module_resolver: Option<InstalledModuleResolver>,
    /// One-shot result side channel from the synchronous import dispatcher to
    /// the `ImportModule` instruction. When populated, the namespace is
    /// available but the importer must park behind this dependency's module
    /// evaluation Promise before executing its next instruction (bd-yn3lv).
    pending_async_module_import: Option<(String, crate::promise_model::PromiseHandle)>,
    /// Active CommonJS module context, if currently evaluating a CJS module.
    active_cjs_context: Option<CjsModuleContext>,
    /// Current module specifier (used to resolve relative imports).
    current_module_specifier: Option<String>,
    /// Generated artifact whose function table owns the active execution.
    ///
    /// This is deliberately distinct from `current_module_specifier`: generated
    /// code resolves modules against its ordinary owner specifier while its
    /// nested function indices belong to the artifact program.
    active_generated_function_artifact: Option<GeneratedFunctionArtifactHandle>,
    /// Source label of the entry module for the active `execute()` call.
    /// Pending top-level await is currently supported only for this module;
    /// imported async-module graph evaluation remains fail-closed.
    entry_module_specifier: Option<String>,
    /// Console output captured for deterministic replay.
    console_output: Vec<ConsoleEntry>,
    /// Total message bytes in `console_output`, held under
    /// `config.max_console_bytes`.
    console_output_bytes: usize,
    /// `console.group` nesting (bd-9vouw.158): later console output is
    /// indented two spaces per level.
    console_group_depth: usize,
    /// `console.count` counters by label.
    console_counts: BTreeMap<String, u64>,
    /// `console.time` starts (performance.now() ticks) by label.
    console_timers: BTreeMap<String, f64>,
    /// Exit status set by `process.exitCode = n` or `process.exit(n)`
    /// (bd-my9hk); `None` means the program never set one.
    process_exit_code: Option<i32>,
    /// Instruction count already converted into virtual wall-clock time
    /// (see [`INSTRUCTIONS_PER_VIRTUAL_MS`]).
    virtual_clock_instruction_mark: u64,
    /// Profiling data collection (optional for performance measurements).
    profiling_data: Option<crate::profiling::Profiler>,
    /// Next timer ID for setTimeout/setInterval (monotonic for determinism).
    next_timer_id: u32,
    /// Active timers for clearTimeout/clearInterval tracking.
    active_timers: std::collections::BTreeMap<u32, ActiveTimer>,
    /// bd-suwvw: per-macrotask timer actions keyed by registration sequence
    /// (see [`PendingTimerTask`]). Entries are drained when their macrotask
    /// fires, so the map only holds in-flight timers.
    pending_timer_tasks: BTreeMap<u64, PendingTimerTask>,
    /// bd-suwvw: timer ids whose handles were `unref()`'d. The idle event
    /// loop drain exits when every pending macrotask is an unref'd (or
    /// cancelled) timer, matching Node's "unref'd timers don't keep the
    /// process alive" semantics.
    unref_timer_ids: BTreeSet<u32>,
    /// bd-9vouw.286: pending `Atomics.waitAsync` waiters, in arrival order
    /// (the order `Atomics.notify` wakes them in).
    atomics_async_waiters: Vec<atomics::AtomicsAsyncWaiter>,
    /// Containment state: whether execution is suspended due to guardplane action.
    #[allow(dead_code)]
    suspended: bool,
    /// Containment state: whether execution is sandboxed (capabilities restricted).
    #[allow(dead_code)]
    sandboxed: bool,
    /// Containment state: whether extension is marked for quarantine.
    #[allow(dead_code)]
    quarantined: bool,
    /// Pending challenge tokens requiring resolution.
    #[allow(dead_code)]
    pending_challenges: Vec<ChallengeToken>,
    /// Evidence records for containment actions taken.
    #[allow(dead_code)]
    containment_evidence: Vec<WitnessEvent>,
    /// Decision receipt log for signed evidence chain.
    decision_receipts: EvidenceLog,
    /// Nondeterminism trace for deterministic replay.
    nondeterminism_trace: NondeterminismTrace,
    /// IFC labels for each register (same indexing as registers vec).
    register_labels: Vec<Label>,
    /// Fast-path invariant (`g2vrp.15`): true when every entry in `register_labels`
    /// is `Label::Public`, skipping per-instruction label reads, clones, and
    /// per-call label-window scans on pure-Public compute frames.
    all_register_labels_public: bool,
    /// Dynamic taint committed into guest-owned aggregate containers. Register
    /// labels alone are insufficient because an object can be aliased before a
    /// later `SetProperty` writes a more confidential value through another
    /// reference. Process-effect request extraction joins these labels
    /// recursively before crossing the provider boundary.
    object_mutation_labels: BTreeMap<ObjectId, Label>,
    /// Physical register indices explicitly pinned via `set_register_label`.
    seeded_register_labels: BTreeSet<usize>,
    /// Aggregate provenance active while an isolated callback runs. Register
    /// writes join this label after per-call frame clearing, so zero-argument
    /// callbacks cannot lose lifecycle/emission context.
    active_inline_callback_context_label: Option<Label>,
    /// Post-dominator implicit-flow PC-label stack (`g2vrp.8`).
    pc_label_stack: Vec<PcLabelFrame>,
    /// Bounded cache of immediate post-dominator tables keyed by
    /// `(instructions_ptr, instructions_len)`.
    ipdom_cache: BTreeMap<(usize, usize), Arc<[usize]>>,
    /// Bounded structured audit trail of runtime IFC sink flow checks.
    ifc_runtime_flow_audit: Vec<IfcRuntimeFlowAuditEntry>,
    /// Optional deterministic epoch (ms) for runtime declassification-receipt
    /// freshness/expiry validation (`bd-9vouw.8`).
    ifc_validation_epoch_ms: Option<u64>,
    /// Transaction probes for isolated callbacks whose caller publishes an
    /// in-flight state before invocation. The innermost probe flips after
    /// CallMethod validates the callee but before any persistent callee setup
    /// (rest arrays, promises, generator records, or guest code); it deliberately
    /// survives module snapshot/restore.
    inline_callback_start_probes: Vec<bool>,
    /// Native GetMethod nesting while selecting Proxy traps. This transient
    /// guard stays outside guest activation snapshots: a handler whose
    /// prototype refers back to its Proxy must not reset the host stack bound.
    proxy_trap_lookup_depth: u32,
    /// WeakMap storage with weak reference semantics.
    weakmap_storage: BTreeMap<ObjectId, WeakMapStorage>,
    /// Exact Symbol identities, descriptions, and global registry state.
    symbol_state: SeedTrackedField<RuntimeSymbolState>,
    /// GC remembered set for tracking old->young generation references.
    gc_remembered_set: RememberedSet,
    /// JIT hot path detection counters for function calls.
    jit_function_call_counts: BTreeMap<u32, u64>,
    /// JIT hot path detection counters for loop backedges.
    jit_loop_iteration_counts: LoopIterationCounters,
    /// Configurable threshold for tier promotion (default: 10,000).
    jit_hot_threshold: u64,
    /// Cold function eviction counter to implement decay policy.
    jit_eviction_counter: u64,
    /// Reclaiming collector state (bd-9vouw.57).
    gc: collector::GcState,
}

impl Drop for InterpreterCore {
    fn drop(&mut self) {
        if self.process_spawn.is_none() {
            return;
        }
        // Execution can exit before the deferred Wait turn (fatal callback,
        // containment, memory budget, or turn-limit exhaustion). Provider Arcs
        // may outlive this core, so do not rely on provider Drop for ownership
        // revocation.
        let handles = self
            .pending_child_process_tasks
            .values()
            .map(|task| task.handle.clone())
            .collect::<BTreeSet<_>>();
        for handle in handles {
            let _ = self.cleanup_process_handle(&handle);
        }
    }
}

/// Resolved public-facing parts of a live key-pair handle: the algorithm,
/// the private material, the public material, and the IFC label carried by
/// the key at derivation time.
type CryptoKeyPairParts = (CryptoKeyPairAlgorithm, Zeroizing<Vec<u8>>, Vec<u8>, Label);

mod core_compact_and_promises;
mod core_dispatch_and_arrays;
mod core_event_loop_and_builtins;
mod core_init_and_state;
mod core_math_and_registers;
mod core_objects_and_descriptors;
mod core_streams_and_ifc;
mod lane_router;

#[allow(unused_imports)]
use lane_router::*;
pub use lane_router::{
    ExecutionEngine, LaneChoice, LaneReason, LaneRouter, QuickJsLane, RoutedResult, V8Lane,
};

#[doc(hidden)]
pub const COMBINED_PRODUCTION_SOURCE: &str = concat!(
    include_str!("baseline_interpreter.rs"),
    "\n",
    include_str!("baseline_interpreter/core_init_and_state.rs"),
    "\n",
    include_str!("baseline_interpreter/core_streams_and_ifc.rs"),
    "\n",
    include_str!("baseline_interpreter/core_dispatch_and_arrays.rs"),
    "\n",
    include_str!("baseline_interpreter/core_compact_and_promises.rs"),
    "\n",
    include_str!("baseline_interpreter/core_event_loop_and_builtins.rs"),
    "\n",
    include_str!("baseline_interpreter/core_objects_and_descriptors.rs"),
    "\n",
    include_str!("baseline_interpreter/core_math_and_registers.rs"),
    "\n",
    include_str!("baseline_interpreter/lane_router.rs"),
);

#[cfg(test)]
#[path = "baseline_interpreter/tests_async_runtime.rs"]
mod async_runtime_tests_current;
#[cfg(test)]
#[path = "baseline_interpreter/tests_core_suite.rs"]
mod tests;
#[cfg(test)]
mod tests_builtins_and_modules;
#[cfg(test)]
mod tests_call_apply_and_timers;
#[cfg(test)]
mod tests_regressions_and_ifc;
