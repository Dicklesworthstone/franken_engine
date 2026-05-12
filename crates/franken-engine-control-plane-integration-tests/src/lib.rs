#![forbid(unsafe_code)]

//! Dedicated package for control-plane integration tests that require
//! `frankenengine-test-support`.
//!
//! Keeping these tests outside `frankenengine-engine` lets source-local
//! library unit tests run without compiling the support-heavy integration
//! harness graph.
//!
//! Run the package through rch with:
//! `rch exec -- env CARGO_INCREMENTAL=0 RUSTFLAGS='-C linker=cc' cargo test -p frankenengine-control-plane-integration-tests`
