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