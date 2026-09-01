//! Trust-zone runtime compatibility and versioned persistence.
//!
//! `compat` retains the historical runtime API and exact legacy-v1 identity
//! bytes. `persistence` adds a self-describing persistence contract without
//! changing retained runtime artifacts.

mod compat;
mod persistence;

pub use compat::*;
pub use persistence::*;
