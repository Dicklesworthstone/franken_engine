# Contributing to FrankenEngine

Thank you for your interest in contributing to FrankenEngine! This guide provides everything you need to get started as a human contributor to this native Rust runtime for adversarial extension workloads.

## Prerequisites

### Required Tools

- **Rust Nightly**: FrankenEngine uses Rust 2024 edition features
  ```bash
  rustup install nightly
  rustup default nightly
  ```

- **Git**: For version control and collaboration
  ```bash
  git --version  # Should be 2.0+
  ```

- **Additional Tools** (recommended):
  ```bash
  # For development workflow
  cargo install cargo-watch
  cargo install cargo-edit
  
  # For code quality
  rustup component add clippy rustfmt
  ```

### Platform Support

FrankenEngine supports Linux, macOS, and Windows with architecture-aware builds. Development is primarily done on Linux, but all platforms are tested in CI.

## Quick Start

### 1. Clone and Build

```bash
git clone https://github.com/Dicklesworthstone/franken_engine.git
cd franken_engine

# Build in development mode
cargo check --all-targets
cargo build --workspace

# Run basic tests
cargo test --workspace
```

### 2. Verify Your Setup

```bash
# Test the CLI
cargo run --bin frankenctl -- version

# Run a simple compile/execute cycle
mkdir -p ./artifacts
echo 'const answer = 40 + 2;' > ./demo.js
cargo run --bin frankenctl -- compile --input ./demo.js --out ./artifacts/demo.compile.json --goal script
cargo run --bin frankenctl -- run --input ./demo.js --extension-id demo-ext --out ./artifacts/demo.run.json
```

## Architecture Overview

FrankenEngine follows a layered architecture from parsing to execution:

```
Source Code (JS/TS)
       ↓
   parser.rs → ast.rs
       ↓
lowering_pipeline.rs (IR0→IR1→IR2→IR3)
       ↓
baseline_interpreter.rs
       ↓
execution_orchestrator.rs
       ↓
   evidence_ledger.rs
```

For detailed architecture documentation, see `docs/ARCHITECTURE_OVERVIEW.md` (when available).

### Key Components

- **Parser**: Converts source code to AST
- **Lowering Pipeline**: Transforms AST through multiple IR levels  
- **Interpreter**: Executes IR3 bytecode
- **Orchestrator**: Manages execution profiles and resource allocation
- **Evidence**: Records cryptographic decision receipts

## Module Organization

The codebase is organized into several key areas:

### Core Runtime (`crates/franken-engine/src/`)
- `parser.rs`, `ast.rs` - Source parsing and AST representation
- `lowering_pipeline.rs` - Multi-stage IR lowering
- `baseline_interpreter.rs` - Core execution engine
- `execution_orchestrator.rs` - Runtime coordination

### Governance & Security
- `capability_*` - Authority and capability management
- `security_epoch.rs` - Temporal security boundaries  
- `evidence_ledger.rs` - Decision receipt generation
- `hash_tiers.rs` - Content addressing and integrity

### Testing & Validation
- `tests/` - Integration tests (one per source module)
- `conformance_*` - Compliance and compatibility validation
- Gate scripts in `scripts/` for CI validation

## Code Conventions

### Rust Standards

- **Edition**: Rust 2024 with nightly features
- **Safety**: `#![forbid(unsafe_code)]` - no unsafe code anywhere
- **Error Handling**: Use `Result<T, E>` consistently, avoid panics in library code
- **Documentation**: All public APIs must have doc comments

### Data Structures

- **Deterministic Collections**: Use `BTreeMap`/`BTreeSet` instead of `HashMap`/`HashSet` for deterministic ordering
- **Serialization**: All types should implement `serde::Serialize` and `serde::Deserialize`
- **Fixed-Point Math**: Use millionths (1_000_000 = 1.0) for deterministic decimal representation

### Modern Rust Features

```rust
// Use let-chains (Rust 2024)
if let Some(x) = expr && condition {
    // ...
}

// Prefer BTreeMap for determinism
let mut map = BTreeMap::new();

// Always forbid unsafe
#![forbid(unsafe_code)]
```

### Module Registration

- Add new modules alphabetically in `lib.rs`
- Each source module must have corresponding integration tests
- Follow the naming pattern: `src/foo.rs` → `tests/foo_integration.rs`

## Development Workflow

### Finding Work

FrankenEngine uses a bead-based task management system:

```bash
# List available work (requires beads tooling)
br list --status open --priority 0-2

# Check task details
br show bd-task-id

# Claim a task
br update bd-task-id --assignee YourName
br update bd-task-id --status in_progress
```

### Implementation Process

1. **Reserve Files**: Use `br` tooling to reserve files you'll modify
2. **Implement**: Write code following conventions above
3. **Format**: `cargo fmt` (required)
4. **Lint**: `cargo clippy -- -D warnings` (must pass)
5. **Test**: `cargo test` (all tests must pass)
6. **Close**: `br close bd-task-id --reason "done: description"`
7. **Commit**: Git commit with proper attribution

### Common Clippy Gotchas

- **collapsible_if + let-chains**: Combine nested if-let statements
- **manual_is_multiple_of**: Use `.is_multiple_of()` for unsigned types only
- **too_many_arguments**: Max 7 function arguments (use structs for more)
- **for_kv_map**: Use `.keys()` when iterating over keys only

### Remote Compilation

The project uses `rch` for remote compilation to handle resource-intensive builds:

```bash
# Check remote build status  
rch status

# For environment variable issues
rch exec 'env CARGO_INCREMENTAL=0 cargo check ...'

# Clean cache corruption
cargo clean && CARGO_INCREMENTAL=0 cargo clippy
```

## Testing

### Unit Tests

Every source module should have comprehensive unit tests (minimum 20 tests per module):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_basic_functionality() {
        // Test implementation
    }
}
```

### Integration Tests

Each source module must have a corresponding integration test file:

- `src/parser.rs` → `tests/parser_integration.rs`
- `src/ast.rs` → `tests/ast_integration.rs`

Integration tests should cover public API contracts, serialization, and cross-module interactions.

### Running Tests

```bash
# All tests
cargo test --workspace

# Specific module
cargo test --test parser_integration

# With output
cargo test --test parser_integration -- --nocapture
```

## Quality Gates

### Pre-commit Requirements

All code must pass these checks before merging:

1. **Compilation**: `cargo check --all-targets`
2. **Formatting**: `cargo fmt --check`  
3. **Linting**: `cargo clippy --all-targets -- -D warnings`
4. **Testing**: `cargo test --workspace`
5. **Documentation**: All public APIs documented

### Performance Standards

- No performance regressions in benchmark suite
- Memory usage should be bounded and predictable
- All optimizations must include correctness proofs

### Security Standards

- All cryptographic operations must be deterministic and reproducible
- Evidence generation for high-impact decisions
- Capability-based access control throughout

## Review Process

### Pull Request Guidelines

1. **Scope**: Keep PRs focused on a single logical change
2. **Tests**: Include tests for all new functionality
3. **Documentation**: Update docs for API changes
4. **Commit Messages**: Use conventional commit format with Co-Authored-By attribution

### Review Checklist

Reviewers will check:
- [ ] Code follows established conventions
- [ ] All tests pass and coverage is adequate
- [ ] Documentation is complete and accurate
- [ ] Performance impact is understood
- [ ] Security implications are considered

## Getting Help

### Documentation

- **README.md**: Project overview and quick start
- **docs/**: Detailed technical documentation
- **Source Comments**: Implementation details and rationales

### Community

- **Issues**: Report bugs and request features via GitHub Issues
- **Discussions**: Technical discussions and questions
- **Agent Coordination**: The project includes AI agents - see AGENTS.md for coordination protocols

### Common Issues

- **Build Failures**: Check `rch status` for remote build infrastructure
- **Test Timeouts**: Large test suites may need increased timeouts
- **File Locks**: Multiple agents can cause file lock contention

## Project Values

### Design Principles

1. **Deterministic First**: All execution must be reproducible
2. **Evidence-Based**: Claims backed by artifacts
3. **Security by Construction**: Built-in containment and authority boundaries
4. **Performance with Proofs**: Optimizations verified for correctness

### Code Quality

- Prefer explicit over implicit behavior
- Fail closed on security-relevant decisions  
- Maintain compatibility with existing evidence chains
- Keep abstractions minimal and well-justified

---

Ready to contribute? Start by exploring the codebase, picking up a small task from the bead system, and following the workflow above. Welcome to FrankenEngine!