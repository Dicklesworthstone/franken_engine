# FrankenEngine Core (Reference Only)

⚠️ **This crate is currently excluded from the workspace and is reference-only.**

## Status: Incomplete Modularization

This crate represents an in-progress modularization effort (commit cb049273) to extract core runtime modules from the main `frankenengine-engine` crate. However, the extraction is incomplete and **does not compile**.

## Missing Critical Modules

The following 5 core modules are referenced throughout the codebase but not yet implemented:

1. **`object_model`** - JavaScript value types, object handles, and runtime representation
2. **`promise_model`** - Promise infrastructure, handles, and settlement outcomes  
3. **`profiling`** - Performance measurement and optimization telemetry
4. **`control_plane`** - Execution control and coordination mechanisms
5. **`trust_zone`** - Security boundaries and isolation primitives

## Impact

These missing modules cause **100+ compilation errors** across multiple files, particularly in:
- `baseline_interpreter.rs` - Heavy usage of `JsValue`, `PromiseHandle`, `SettledOutcome`
- Other core execution modules that depend on runtime object model

## Resolution Path

**Do not add this crate to the workspace** until the modularization effort is completed. The missing modules represent fundamental architectural components that require careful design and implementation.

To complete the modularization:
1. Extract the 5 missing modules from `frankenengine-engine`
2. Ensure all cross-module dependencies are properly defined
3. Validate the extracted modules compile and pass tests
4. Re-add to workspace in `Cargo.toml`

Until then, this directory serves as a **reference for the intended modular architecture** but should not be built or deployed.