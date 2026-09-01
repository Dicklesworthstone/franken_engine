//! Capability-token compatibility and SHA-256-v2 persistence.
//!
//! `compat` preserves the historical token wire format and legacy-v1 identity.
//! `versioned` provides self-describing SHA-256-v2 token identities, explicit
//! checkpoint-ID algorithms, identity recomputation during verification, and
//! verified migration of retained legacy tokens.

mod compat;
mod versioned;

pub use compat::*;
pub use versioned::*;
