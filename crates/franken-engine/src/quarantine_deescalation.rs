//! Quarantine re-admission compatibility and SHA-256-v2 evidence.
//!
//! `compat` retains the exact V1 decision/receipt API and historical signature
//! preimages. `versioned` adds the self-describing SHA-256-v2 write path plus
//! verified legacy migration provenance without changing retained artifacts.

mod compat;
mod versioned;

pub use compat::*;
pub use versioned::*;
