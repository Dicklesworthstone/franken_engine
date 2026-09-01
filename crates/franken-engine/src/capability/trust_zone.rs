//! Trust-zone runtime compatibility and versioned persistence.
//!
//! The parent capability module imports the names required by the historical
//! implementation. `persistence` adds a self-describing contract without
//! changing retained runtime artifacts.

use super::{CapabilityProfile, RuntimeCapability};

mod compat;
mod persistence;

pub use compat::*;
pub use persistence::*;
