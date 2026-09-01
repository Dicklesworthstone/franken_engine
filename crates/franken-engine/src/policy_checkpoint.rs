//! Policy-checkpoint compatibility and SHA-256-v2 persistence.
//!
//! `compat` preserves the historical checkpoint API and legacy-v1 IDs.
//! `versioned` supplies the self-describing SHA-256-v2 chain used by new
//! persisted checkpoints and by verified legacy migrations.

mod compat;
mod versioned;

pub use compat::*;
pub use versioned::*;
