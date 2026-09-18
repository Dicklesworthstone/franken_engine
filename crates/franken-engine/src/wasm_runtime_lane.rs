//! WebAssembly execution and runtime-lane integration.
//!
//! [`numeric`] is the shared Rust-native executable VM. It validates numeric
//! functions, structured control flow, linear memory and globals before
//! publication, with explicit instruction, stack, call-depth and memory limits.
//! [`numeric::WasmNumericVm::instantiate`] creates isolated persistent state;
//! repeated [`numeric::WasmNumericInstance::call_export`] calls retain that
//! instance's completed writes, including writes preceding a later trap.
//!
//! The ABI-routing and reactive-signal surfaces remain available at their
//! existing public paths. In particular, [`WasmModuleImportRoute::call_export`]
//! remains the constant-body compatibility route, not an alias for the numeric
//! VM. This module does not grant imported host capabilities or expose a new
//! JavaScript module-loader route.

#[path = "wasm_runtime_lane/lane.rs"]
mod lane;
pub use lane::*;

#[path = "wasm_numeric_vm.rs"]
pub mod numeric;
