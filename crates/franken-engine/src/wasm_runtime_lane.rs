//! WebAssembly execution and runtime-lane integration.
//!
//! [`numeric`] is the shared Rust-native executable VM. It validates numeric
//! functions, structured control flow, linear memory and globals before
//! publication, with explicit instruction, stack, call-depth and memory limits.
//! [`numeric::WasmNumericVm::instantiate`] creates isolated persistent state;
//! repeated [`numeric::WasmNumericInstance::call_export`] calls retain that
//! instance's completed writes, including writes preceding a later trap.
//! [`numeric::WasmNumericInstance::begin_call`] prepares a cooperatively sliced
//! export invocation. [`WasmNativeInstance::begin_call`] preserves the resolver
//! policy boundary and reauthorizes every resume. Startup and complete commands
//! also have cooperative, current-policy-checked task APIs.
//!
//! The ABI-routing and reactive-signal surfaces remain available at their
//! existing public paths. In particular, [`WasmModuleImportRoute::call_export`]
//! remains the constant-body compatibility route, not an alias for the numeric
//! VM. [`crate::module_resolver::DeterministicModuleResolver::load_wasm`] resolves
//! capability-gated imports into [`WasmNativeModule`] for native execution.
//! [`WasmNativeInstance`] rechecks the current policy before startup, calls and
//! state inspection. This is an embedding API, not JavaScript import-expression
//! evaluation or automatic ESM namespace binding. Host imports are unbound by
//! default; [`WasmNativeModule::instantiate_with_imports`] explicitly links
//! providers within the module's declared authority and current policy.

#[path = "wasm_runtime_lane/lane.rs"]
mod lane;
pub use lane::*;

#[path = "wasm_numeric_vm.rs"]
pub mod numeric;

#[path = "wasm_runtime_lane/imports.rs"]
mod imports;
pub use imports::{
    WasmNativeCall, WasmNativeCallStep, WasmNativeInstance, WasmNativeLoadError, WasmNativeModule,
};

#[path = "wasm_runtime_lane/host_replay.rs"]
pub mod host_replay;

#[path = "wasm_runtime_lane/scheduler.rs"]
pub mod scheduler;

/// Explicit, bounded Preview 1 providers; no process environment or ambient I/O.
#[path = "wasm_runtime_lane/wasi_preview1.rs"]
pub mod wasi_preview1;

/// Shared admission reservations for bounded native linear-memory envelopes.
#[path = "wasm_runtime_lane/memory_pool.rs"]
pub mod memory_pool;

/// Non-refillable shared execution quotas; no ambient work or host authority.
#[path = "wasm_runtime_lane/work_pool.rs"]
pub mod work_pool;

#[path = "wasm_runtime_lane/command.rs"]
pub mod command;
