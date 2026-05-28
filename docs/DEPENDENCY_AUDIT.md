# Cross-Repo Dependency Audit

**Generated:** 2026-04-16T13:42:00Z  
**Bead:** RC-6 Cross-Repo Dependency Isolation

## External Path Dependencies

The following external crates are referenced via path dependencies in `/data/projects/franken_engine/crates/franken-engine/Cargo.toml`:

### Asupersync Integration Crates

1. **franken-kernel** 
   - Path: `/dp/asupersync/franken_kernel`
   - Feature gate: `asupersync-integration` 
   - Status: Optional dependency
   - Purpose: Core kernel functionality for governance operations

2. **franken-decision**
   - Path: `/dp/asupersync/franken_decision` 
   - Feature gate: `asupersync-integration`
   - Status: Optional dependency
   - Purpose: Decision-making infrastructure for policy enforcement

3. **franken-evidence**
   - Path: `/dp/asupersync/franken_evidence`
   - Feature gate: `asupersync-integration` 
   - Status: Optional dependency
   - Purpose: Evidence collection and verification for audit trails

## Feature Gate Configuration

### Default Features
- `default = ["asupersync-integration"]` - Enables all external dependencies by default

### Available Build Modes

#### Standalone Mode
```bash
cargo check --no-default-features
```
- Compiles without external asupersync dependencies
- Suitable for development environments without sibling repositories
- Governance modules compile but emit warnings when used without real backends

#### Full Integration Mode  
```bash
cargo check --all-features
```
- Includes all asupersync dependencies
- Full governance and policy functionality available
- Requires sibling repositories at expected paths

## Dependency Availability Assessment

| Crate | Path | Exists | Compiles | API Surface |
|-------|------|--------|----------|-------------|
| franken-kernel | /dp/asupersync/franken_kernel | ✓ | ✓ | Stable |
| franken-decision | /dp/asupersync/franken_decision | ✓ | ✓ | Stable |  
| franken-evidence | /dp/asupersync/franken_evidence | ✓ | ✓ | Stable |

## External crates.io Dependencies — perf-track adds

### `bumpalo` (ALIEN-2 region arena)

- **Path:** crates.io (`bumpalo`)
- **Introduced by:** PERF-ALIEN-2.2 (`bd-o4cbn.10.2`, commit `4c38f5c1`)
- **Used by:** `crates/franken-engine/src/lowering_arena.rs` (`LoweringArena`
  wraps `bumpalo::Bump`; `bumpalo::collections::Vec` is used for per-pass
  scratch in `lower_ir2_to_ir3`).
- **Why a region arena.** Per-pass scratch `Vec`s in the IR lowering pipeline
  used to pay N independent `global_allocator` `free` calls when the pass
  ended; the arena turns that into one bulk drop / `reset`, dropping allocator
  traffic on the parser-arena + lowering hot paths (see ALIEN-2 row in
  `docs/PERFORMANCE_BASELINE.md` for measured deltas).
- **Determinism contract.** The arena is a **pure allocation-strategy refactor**:
  emitted ExecIR (`Ir3Module::canonical_bytes` / `content_hash`) is byte-
  identical to pre-ALIEN-2 output, pinned by the ALIEN-2.3 golden
  `alien2_ir3_output_is_byte_identical_golden` in
  `crates/franken-engine/src/lowering_pipeline.rs` (commit `a8510cad`). Any
  future arena/region change that perturbs IR output trips that golden.
- **Build mode coverage.** Standalone + full integration both build `bumpalo`;
  it has no `asupersync-integration` feature gate.

## Recommendations

1. **CI Integration**: Verify both build modes in CI pipelines
2. **Documentation**: Update README with build mode instructions
3. **Fallback Behavior**: Governance modules should provide clear error messages when used without backends
4. **API Contracts**: Maintain stable interfaces for external crate integration points

## Usage Guidance

For developers working without the full asupersync repository layout:
- Use standalone mode for development: `cargo check --no-default-features`
- Governance features will compile but warn at runtime without real backends
- Integration tests requiring full governance should be feature-gated