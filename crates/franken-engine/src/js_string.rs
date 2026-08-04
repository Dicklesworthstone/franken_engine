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
//! documentation, the canonical invariant, the exact property-map carrier,
//! and the unit-test suite.

pub use frankenengine_core::js_string::{CodeUnits, ExactPropertyMap, JsString};

use crate::deterministic_serde::CanonicalValue;

/// Convert the shared exact string carrier into the engine crate's canonical
/// value type. The core and engine deterministic serializers intentionally
/// remain separate types even though they use the same wire shape.
pub(crate) fn canonical_js_string_value(value: &JsString) -> CanonicalValue {
    if let Some(text) = value.as_str() {
        CanonicalValue::str(text)
    } else {
        CanonicalValue::map_from_entries([(
            "$wtf16",
            CanonicalValue::Array(
                value
                    .encode_utf16()
                    .map(|unit| CanonicalValue::U64(u64::from(unit)))
                    .collect(),
            ),
        )])
    }
}
