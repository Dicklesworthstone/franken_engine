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

**DEVIATION**: Typed-heavy persistence stores are implemented through generic `storage_adapter.rs` 
`StoreRecord/StoreQuery` interfaces instead of `/dp/sqlmodel_rust` typed model/schema layers as 
mandated above. Specifically:

- `ReplacementLineage`, `IfcProvenance`, and `SpecializationIndex` stores use raw frankensqlite 
  integration points (`frankensqlite::replacement::lineage_log`, etc.) instead of sqlmodel_rust 
  typed boundaries as documented in `docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md`.

**Impact**: Type safety and schema validation expected from sqlmodel_rust typed layers is bypassed. 
Store invariants that should be enforced at compile-time through typed boundaries can drift into 
runtime validation or be missed entirely.

**Required Fix**: **P0 Follow-up Bead Filed** - Replace generic `StoreRecord` implementations with 
concrete `/dp/sqlmodel_rust` model/schema APIs for inventory rows marked "sqlmodel_rust on 
frankensqlite", or add policy guards that reject raw implementations for typed-heavy stores.

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
- mathematically explicit runtime security for untrusted extension code
- deterministic replay and auditable decision artifacts
- category-defining performance/security posture beyond Node/Bun defaults

### Non-Negotiable Architectural Constraints

- No `rusty_v8`, `rquickjs`, or equivalent binding-led core execution path.
- `legacy_quickjs/` and `legacy_v8/` are reference corpora only.
- Adaptive systems require deterministic safe-mode fallback.
- Significant claims require reproducible artifacts.

---

## Working With Plans and Artifacts

- Plan authority for this program lives in:
  - `/dp/franken_engine/PLAN_TO_CREATE_FRANKEN_ENGINE.md`
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
