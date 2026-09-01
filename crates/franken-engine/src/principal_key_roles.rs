//! Principal key-role compatibility and SHA-256-v2 owner bundles.
//!
//! `compat` retains the historical role registry and raw-ID bundle API.
//! `versioned` provides strict legacy bundle verification plus a self-describing
//! SHA-256-v2 owner bundle that binds the owner principal into the persisted
//! identity.

mod compat;
mod versioned;

pub use compat::*;
pub use versioned::*;
