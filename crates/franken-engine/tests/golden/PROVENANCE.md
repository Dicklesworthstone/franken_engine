# Golden File Provenance

## Regeneration Convention (Project-Wide)

All franken-engine golden tests honor a single environment variable:

```bash
UPDATE_GOLDENS=1 cargo test ...
```

Setting `UPDATE_GOLDENS=1` puts every golden-aware test into write mode
(creating or rewriting its golden fixture); leaving it unset puts every
test into compare mode. There is no per-suite alias — older sites that
used `UPDATE_GOLDEN`, `REGENERATE_GOLDEN`, or `BLESS_GOLDEN` have all
been migrated (bd-ub6x8.2).

## Generation

Golden files in this directory were generated from adversarial fuzzing harness outputs to lock down behavior for regression testing.

### Source
- **Test File**: `tests/golden_fuzz_regression.rs`
- **Base Harness**: `tests/fuzz_adversarial.rs` parser boundary corpus
- **Generator**: `run_parser_boundary_golden()` function

### Generation Command
```bash
# Generate/update golden files
UPDATE_GOLDENS=1 cargo test golden_fuzz_regression

# Normal comparison mode
cargo test golden_fuzz_regression
```

### Data Sources
- **Parser boundary cases**: Curated test vectors exercising edge cases
- **Regression cases**: Specific inputs that have caused issues historically
- **Fuzzing findings**: Outputs from adversarial fuzzing campaigns

### Scrubbing Applied
- SHA256 hashes → `sha256:[HASH]` (for readability, hashes are deterministic)
- Memory addresses → `0x[ADDR]` (non-deterministic)

### File Structure
- `parser_boundary_case_XX.json`: Sequential test cases
- `parser_boundary_max_recursion.json`: High recursion depth case
- `parser_boundary_minimal_module.json`: Minimal valid module case

### Review Process
1. Run `UPDATE_GOLDENS=1 cargo test golden_fuzz_regression`
2. Review all changes: `git diff tests/golden/`
3. Verify changes are intentional (not regressions)
4. Commit approved golden updates

### Last Updated
Generated with:
- Rust: 2024 edition
- frankenengine-engine: v0.1.0
- Parser: CanonicalEs2020Parser
- Mode: ScalarReference

## Purpose

These golden files ensure that:
1. Parser behavior remains consistent across code changes
2. Fuzzing-discovered edge cases don't regress
3. Parse event IR generation is stable
4. Error diagnostics maintain expected structure
5. Deterministic parsing guarantees are preserved