# AGENTS.md — franken_engine

> Guidelines for AI coding agents working in this Rust codebase.

---

## RULE 0 - THE FUNDAMENTAL OVERRIDE PREROGATIVE

If the user tells you to do something, even if it conflicts with guidance below, follow the user.

---

## RULE NUMBER 1: NO FILE DELETION

**NEVER delete a file or folder without explicit written user permission.**

- This includes files you created during the current session.
- If deletion is required, ask first with exact paths and wait for explicit approval.

---

## Irreversible Git & Filesystem Actions — DO NOT EVER BREAK GLASS

1. Forbidden without explicit user authorization in the same message:
   - `git reset --hard`
   - `git clean -fd`
   - `rm -rf`
   - any command that can overwrite/delete user data
2. No guessing: if unsure what a command affects, stop and ask.
3. Prefer safe alternatives (`git status`, `git diff`, backups, non-destructive moves).
4. If approved, restate exact command + affected paths before running.
5. Record in final response: user authorization text, command run, execution time.

---

## Git Branch: ONLY `main`, NEVER `master`

- Default branch is `main`.
- Never introduce `master` references in docs/scripts.
- If a release workflow requires mirror branch sync, do it explicitly from `main`.

---

## Toolchain: Rust & Cargo

Use Cargo only.

- Edition: Rust 2024
- Unsafe code: forbidden in repository code (`#![forbid(unsafe_code)]`)
- Configuration source of truth: `Cargo.toml`

### Workspace Structure

- `crates/franken-engine` (`frankenengine-engine`): core runtime engine substrate
- `crates/franken-extension-host` (`frankenengine-extension-host`): extension-host core and policy/runtime-defense surfaces

### Repository Split Contract (Critical)

- `/dp/franken_engine` is the canonical engine repository.
- `/dp/franken_node` is the compatibility/product repository.
- Dependency direction is one-way:
  - `franken_node` -> `franken_engine`
- Do not reintroduce forked engine crates inside `franken_node`.

### Sibling Repo Reuse Policy (Binding)

- For advanced console/TUI surfaces relevant to this project, use `/dp/frankentui`.
- For SQLite-backed persistence, use `/dp/frankensqlite`; use `/dp/sqlmodel_rust` when typed model/schema layers are beneficial.
  - Local engine adapter traits are allowed only as narrow call-shape seams to `/dp/frankensqlite`; WAL, PRAGMA, journal-mode, and migration policy must be applied by the frankensqlite-backed implementation, not hard-coded in `franken_engine`.
- For service/API control surfaces, prefer reuse from `/dp/fastapi_rust` when relevant.
- Do not build parallel local replacements without explicit user approval.

### Current Deviations (Requiring Follow-up)

**DEVIATION RESOLVED** (2026-05-21): Typed-heavy persistence stores routing through generic storage_adapter - **RESOLVED** via `bd-cixqu.12.1` audit.

**Original Issue**: Documentation claimed `ReplacementLineage`, `IfcProvenance`, and `SpecializationIndex` stores used raw frankensqlite integration points instead of sqlmodel_rust typed boundaries.

**What Actually Happened**: Audit found these stores *are* correctly implemented as sqlmodel_rust-backed:
- `ShadowEvidenceJournal` → `sqlmodel_rust::ShadowEvidenceJournalEntry` ✅
- `ReplacementLineage` → `sqlmodel_rust::ReplacementLineageEntry` ✅  
- `IfcProvenance` → `sqlmodel_rust::IfcProvenanceEntry` ✅
- `SpecializationIndex` → `sqlmodel_rust::SpecializationIndexEntry` ✅

**Retrospective**: The prose was stale. These stores already use typed boundaries via `typed_persistence_models.rs::TypedStoreRecord` trait with proper validation, SQLModel integration, and fail-closed policy enforcement. The only identified issue was a documentation inconsistency for `PlasWitness` (inventory says sqlmodel_rust but code implements raw frankensqlite).

**Reference**: See audit report at `crates/franken-engine/src/storage_adapter_audit_report.md` (bd-cixqu.12.1).

---

## Code Editing Discipline

### No Script-Based Code Rewrites

- Do not run broad regex/scripts to rewrite many source files.
- Make targeted, manual edits.

### No File Proliferation

- Prefer modifying existing files.
- Do not create suffix variants like `*_v2.rs`, `*_new.rs`, `*_improved.rs`.

### Backwards Compatibility

- Do not add temporary compatibility shims that create long-term debt.
- Implement correct semantics directly unless user requests compatibility-only behavior.

---

## Compiler Checks (CRITICAL)

After substantive code changes, run:

```bash
cargo check --all-targets
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

If any step fails, fix properly before finishing.

---

## Testing

### Baseline

```bash
cargo test
```

### Policy

- Add/maintain focused unit tests alongside changed logic.
- Prefer deterministic tests and replay-friendly fixtures.
- For concurrency-sensitive logic, include cancellation/race/regression coverage.

---

## Project Mission (franken_engine)

FrankenEngine is the native runtime heart for `franken_node`, with goals:

- de novo Rust-native execution lanes (no engine bindings for core execution)
- mathematically explicit runtime security models for untrusted extension code,
  with current proof state bounded by `docs/FORMAL_RUNTIME_SECURITY_MODEL_V1.md`,
  the claim-to-proof matrix, and executable IFC/capability invariant tests
- deterministic replay and auditable decision artifacts
- high-performance runtime with mathematically explicit security guarantees

### Non-Negotiable Architectural Constraints

- No `rusty_v8`, `rquickjs`, or equivalent binding-led core execution path.
- `legacy_quickjs/` and `legacy_v8/` are reference corpora only.
- Adaptive systems require deterministic safe-mode fallback.
- Significant claims require reproducible artifacts (see `scripts/reproduce.sh`).

---

## Working With Plans and Artifacts

- Plan authority for this program lives in:
  - `/dp/franken_engine/docs/plans/PLAN_TO_CREATE_FRANKEN_ENGINE.md`
- Keep plan updates coherent with actual repository topology.
- When changing architecture-level decisions, update split-contract docs in both repos.

---

## Session Completion Checklist

Before ending a substantial coding session:

1. Run compiler/lint/format gates.
2. Run relevant tests.
3. Summarize exactly what changed and why.
4. Call out any unverified or deferred items clearly.

If destructive commands were run under approval, include the mandatory audit record.
