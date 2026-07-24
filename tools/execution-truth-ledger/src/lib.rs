#![forbid(unsafe_code)]

// Compile the exact production module through a dependency-minimal package so
// the evidence gate stays operable even when unrelated runtime dependencies do
// not resolve or compile.
#[path = "../../../crates/franken-engine/src/execution_truth_ledger.rs"]
pub mod execution_truth_ledger;

#[path = "../../../crates/franken-engine/src/verification_coverage_contract.rs"]
pub mod verification_coverage_contract;
