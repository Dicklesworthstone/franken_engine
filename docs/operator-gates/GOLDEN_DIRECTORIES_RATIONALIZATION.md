# Golden Directories Rationalization

> Canonical-location decision and migration plan for the four golden-fixture
> roots under `crates/franken-engine/tests/`.

**Bead:** bd-ub6x8.6 (parent) · bd-ub6x8.6.1 (this decision + provenance docs;
file moves deferred). See [`crates/franken-engine/tests/golden/PROVENANCE.md`](
../../crates/franken-engine/tests/golden/PROVENANCE.md) for the canonical
fixture inventory.

## Why this decision exists

The audit at bd-ub6x8.6 found four different top-level directories serving the
same purpose under `crates/franken-engine/tests/`:

| Directory | Format | Subdirs | PROVENANCE |
|-----------|--------|---------|------------|
| `tests/golden/` | text (`.golden`, `.txt`) + lazily-blessed top-level JSON | 6 + top-level | yes |
| `tests/goldens/` | JSON | 6 | now yes (bd-ub6x8.6.1) |
| `tests/golden_tests/` | CLI capture JSON | flat | now yes (bd-ub6x8.6.1) |
| `tests/golden_vectors/` | versioned wire-format JSON | flat | now yes (bd-ub6x8.6.1) |

A reader looking for "where is the React-compilation golden?" had to grep
across all four. New tests were added to whichever directory was nearest,
not by any principle. The skill recommendation
([testing-golden-artifacts]) is **one canonical location, subdir by feature,
mandatory PROVENANCE.md per subdir**.

## Decision

**Canonical location: `crates/franken-engine/tests/golden/<feature>/`.**

- Singular `golden/` (not plural `goldens/`).
- One subdirectory per feature / owning suite.
- Each subdirectory documented in
  `crates/franken-engine/tests/golden/PROVENANCE.md` under
  "Subdirectory Fixtures".
- Top-level fixtures (single-file goldens) remain at
  `tests/golden/<test_name>.golden` / `.json` / `.txt` / `.hex`.

### Why `tests/golden/` (singular)

- It is already the largest root (8 subdirs, ~50 fixtures) and the only
  one with a complete PROVENANCE.md.
- The skill's "Pattern 1: Exact Golden" examples use the singular.
- Singular forms read better in subdir paths
  (`tests/golden/cli/...` vs `tests/goldens/cli/...`).

### Why subdir-by-feature (not subdir-by-format)

A reader chasing a regression starts from the failing test name, not the
on-disk encoding. Grouping by feature (`react_compilation/`, `cli/`,
`wire_vectors/`) maps directly onto the owning test's name and keeps
related fixtures co-located even when one test emits multiple formats.

## Migration plan (deferred)

The actual file moves are deferred to a follow-up bead. They require
updating every owning test's hard-coded fixture path, all of which are
currently locked by other agents at the time bd-ub6x8.6.1 was filed
(GoldenLynx held the parent, HazyAnchor / CrimsonDeer / MistyRobin held
exclusive locks across the affected test source files).

### Source → target mapping

| Today | Tomorrow | Owning test |
|-------|----------|-------------|
| `tests/goldens/ir/` | `tests/golden/ir/` | `src/lowering_pipeline.rs::tests` |
| `tests/goldens/evidence/` | `tests/golden/evidence/` (note collision-free: `tests/golden/evidence_ledger/` already exists; pick a distinct name, e.g. `golden/evidence_bundle/`) | `src/benchmark_evidence_bundle.rs::tests` |
| `tests/goldens/certificates/` | `tests/golden/certificates/` | `tests/certificate_golden_tests.rs` |
| `tests/goldens/react_compilation/` | `tests/golden/react_compilation/` | `tests/react_compilation_golden.rs` + `src/bin/generate_react_goldens.rs` |
| `tests/goldens/policy_theorem_compiler/` | `tests/golden/policy_theorem_compiler/` | `tests/policy_theorem_compiler_integration.rs` |
| `tests/goldens/benchmark_diagnostic/` | `tests/golden/benchmark_diagnostic/` | `tests/benchmark_diagnostic_golden.rs` |
| `tests/golden_tests/*.json` | `tests/golden/cli/*.json` | `tests/cli_golden.rs` |
| `tests/golden_vectors/*` | `tests/golden/wire_vectors/*` | many — see `tests/golden_vectors/PROVENANCE.md` |

### Mechanical steps (for the migration bead)

1. `git mv` each fixture into its target subdir.
2. Update the path constants in every owning test source file (the
   "Owning test" column above lists each call site; the path helpers
   are typically named `*_golden_path`, `evidence_golden_path`,
   `golden_path`, etc.).
3. Add a stanza per migrated subdir to
   `tests/golden/PROVENANCE.md` (a reader-facing inventory; cross-link
   from the old PROVENANCE.md files for one release before removing them).
4. Run `UPDATE_GOLDENS=1 cargo test` and confirm no fixture is
   accidentally rewritten (the bytes must be byte-identical to the
   pre-move content).
5. Run the full test suite under default (compare) mode and confirm
   no fixture-mismatch panics.
6. Update the `.gitignore` patterns under `crates/franken-engine/tests/`
   so `.actual` siblings are covered in the new layout (the existing
   pattern at `tests/golden/.gitignore` is the template — bd-ub6x8.15
   landed a unified policy).
7. Remove the three drained source directories.
8. Update `tests/golden/PROVENANCE.md`'s "Other Golden Roots" section
   (lines 200–222) once those directories no longer exist.

### Non-goals (for the migration bead)

- Changing the on-disk encoding of any fixture.
- Restructuring within `tests/golden/<existing-subdir>/` (those are
  already at their canonical location).
- Pulling in `insta` (tracked separately under bd-ub6x8.11).
- Consolidating the helper functions (tracked under bd-ub6x8.3 /
  bd-ub6x8.3.1).

## Status

- ✅ Decision recorded (this file, bd-ub6x8.6.1).
- ✅ `tests/goldens/PROVENANCE.md` (bd-ub6x8.6.1).
- ✅ `tests/golden_tests/PROVENANCE.md` (bd-ub6x8.6.1).
- ✅ `tests/golden_vectors/PROVENANCE.md` (bd-ub6x8.6.1).
- ⏳ File moves + owning-test path updates — deferred (bd-ub6x8.6).

[testing-golden-artifacts]:
  https://github.com/jeffreyemanuel/jeffreys-skills.md (skill ID:
  `testing-golden-artifacts`)
