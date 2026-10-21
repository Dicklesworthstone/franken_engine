# FrankenEngine Core

This crate is a member of the root workspace and a path dependency of
`frankenengine-engine`.

## Status: Integrated Runtime Core

This crate extracts core runtime modules from `frankenengine-engine`. Workspace
membership does not establish API parity between the two crates; changes to
shared behavior still require tests through each consuming runtime.

## Extracted Runtime Modules

The following core modules are extracted from `frankenengine-engine` for standalone compileability:

1. **`object_model`** - JavaScript value types, object handles, and runtime representation
2. **`promise_model`** - Promise infrastructure, handles, and settlement outcomes  
3. **`profiling`** - Performance measurement and optimization telemetry
4. **`control_plane`** - Execution control and coordination mechanisms
5. **`capability`** - Capability and permission primitives for constrained execution

## Workspace Integration

Run focused checks from the repository root:

```bash
cargo check -p frankenengine-core --all-targets
cargo clippy -p frankenengine-core --all-targets -- -D warnings
cargo test -p frankenengine-core
```

Follow the repository's remote-build requirements when executing Cargo. Focused
checks supplement the full workspace gates; they do not replace them.
