//! Revocation-chain compatibility and SHA-256-v2 persistence.
//!
//! `compat` retains the historical raw-ID chain API. `versioned` supplies a
//! self-describing SHA-256-v2 chain whose revocation, event, predecessor, and
//! head identities are recomputed during verification rather than trusted from
//! persisted bytes.

mod compat;
mod versioned;

pub use compat::*;
pub use versioned::*;
