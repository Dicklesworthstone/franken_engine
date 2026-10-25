#![forbid(unsafe_code)]

//! Dedicated package for control-plane integration tests and the public
//! Buffer API target. The control-plane targets use `frankenengine-test-support`
//! or the non-authoritative TEE test simulator.
//!
//! Keeping these tests outside `frankenengine-engine` lets source-local
//! library unit tests run without compiling the support-heavy integration
//! harness graph.
//! The Buffer target also avoids building unrelated engine binary targets.
//! Package defaults forward the engine's defaults; `--no-default-features`
//! retains the explicit Asupersync/mock-TEE test dependency features.
//!
//! Focused public API coverage:
//! `cargo test -p frankenengine-control-plane-integration-tests --test buffer_value_bd_9vouw_104`
//!
//! Run the package through rch with:
//! `env -u CARGO_ENCODED_RUSTFLAGS rch exec -- env -u CARGO_ENCODED_RUSTFLAGS CARGO_INCREMENTAL=0 RUSTFLAGS='-C linker=cc -Clinker-features=-lld' cargo test -p frankenengine-control-plane-integration-tests`
