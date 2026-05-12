# FrankenEngine Core

⚠️ **This crate is currently excluded from the workspace.**

## Status: Standalone Manifest Compileable

This crate represents an in-progress modularization effort to extract core runtime modules from the main `frankenengine-engine` crate. The standalone crate manifest is expected to compile, but workspace integration remains a separate follow-up because the public API boundary still needs deliberate validation.

## Extracted Runtime Modules

The following core modules are extracted from `frankenengine-engine` for standalone compileability:

1. **`object_model`** - JavaScript value types, object handles, and runtime representation
2. **`promise_model`** - Promise infrastructure, handles, and settlement outcomes  
3. **`profiling`** - Performance measurement and optimization telemetry
4. **`control_plane`** - Execution control and coordination mechanisms
5. **`capability`** - Capability and permission primitives for constrained execution

## Workspace Integration

**Do not add this crate to the workspace** until the integration pass validates the extracted API boundary against the full workspace.

Before re-adding it to the root workspace:
1. Validate the standalone manifest and focused runtime tests.
2. Audit the copied runtime modules for API drift against `frankenengine-engine`.
3. Run the full workspace compiler, lint, format, and test gates with `franken-core` included.

Until then, this directory should be built directly through `cargo --manifest-path crates/franken-core/Cargo.toml ...` rather than as a workspace member.
