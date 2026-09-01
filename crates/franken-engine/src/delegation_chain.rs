//! Delegation-chain compatibility and SHA-256-v2 authority verification.
//!
//! `compat` preserves the historical raw-ID delegation API. `versioned`
//! verifies chains of self-describing v2 capability tokens against
//! algorithm-tagged checkpoint and revocation identities.

mod compat;
mod versioned;

pub use compat::*;
pub use versioned::*;
