//! Engine string value backing with UTF-16 lone-surrogate support (bd-neika).
//!
//! The canonical implementation lives in `frankenengine_core::js_string`
//! (relocated for bd-2vzgi): the engine depends on `franken-core`, not the
//! other way around, so sharing one `JsString` definition requires it to sit
//! below the engine in the dependency graph. This module re-exports the type
//! so every existing `crate::js_string::JsString` path — and the serde wire
//! format, equality/ordering semantics, and the inherent `encode_utf16`
//! shadowing trick documented on the type — is unchanged for engine code.
//!
//! See `crates/franken-core/src/js_string.rs` for the full module
//! documentation, the canonical invariant, and the unit-test suite.

pub use frankenengine_core::js_string::{CodeUnits, JsString};
