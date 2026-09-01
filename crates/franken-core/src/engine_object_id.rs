//! Version-aware EngineObjectId derivation for security-critical state.
//!
//! The historical unversioned APIs are isolated in `compat` and retain their
//! exact legacy-v1 bytes. New persisted or signed consumers must use the
//! version-tagged APIs re-exported from `versioned` and `wire`.

mod compat;
mod display;
mod versioned;
mod wire;

pub use compat::*;
pub use versioned::*;
pub use wire::*;
