#![forbid(unsafe_code)]

// Compile the exact production contract through a dependency-minimal package
// so a broken runtime or sibling path dependency cannot suppress a truthful
// inventory/validation verdict.
#[path = "../../../crates/franken-engine/src/intl_surface_contract.rs"]
pub mod intl_surface_contract;
