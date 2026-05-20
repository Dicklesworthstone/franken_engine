## 2026-05-20 Review Round 1 - P1 Study

Areas reviewed:
- Recent runtime/value representation churn in `crates/franken-engine/src/baseline_interpreter.rs` and baseline interpreter integration tests.
- Recent attestation canonical-byte framing changes in `crates/franken-engine/src/attestation_handshake.rs` and `crates/franken-engine/src/attested_execution_cell.rs`.
- Recent revocation/degraded-mode policy-id binding changes in `crates/franken-engine/src/revocation_freshness.rs`.
- Recent IR/lowering destructuring parameter semantics in `crates/franken-engine/src/lowering_pipeline.rs`.

Findings:

- [HIGH] `crates/franken-engine/tests/baseline_interpreter_integration.rs:4056`, `:9298`, `:9423`, `:9483`, `:9605` - `Value::str(...)` was called with `Path::display()` values after the string payload migration to `Arc<str>`. `std::path::Display` does not implement `Into<Arc<str>>`, so these integration tests fail to compile under `cargo check --all-targets`. Root cause: allocation-reduction migration replaced `display().to_string()` with `display()` at public test call sites. Fix: restored explicit `.display().to_string()` conversion at each assertion.

- [HIGH] `crates/franken-engine/tests/baseline_interpreter_edge_cases.rs:1964`, `:1986`, `:1997`, `:2024` - `Ok(Value::Str(s)) => assert_eq!(s, "...")` compared `Arc<str>` bindings directly with string literals after the `Value::Str` representation changed. This broke focused test compilation for `baseline_interpreter_edge_cases`. Root cause: test assertions were not migrated with the runtime value representation change. Fix present in current tree: compare `s.as_ref()` to the literal.

- [MEDIUM] `crates/franken-engine/src/revocation_freshness.rs:519` - review of the recent degraded-mode replay hardening found that a randomly derived controller `policy_id` would make `RevocationFreshnessController::new(config, zone)` non-replayable across identical config/zone constructions, undermining deterministic evidence replay and cross-controller override validation. Root cause: policy identity was coupled to fresh OS randomness instead of stable policy inputs. Fix present in current working tree: derive policy id from length-prefixed config and zone bytes via `derive_policy_id`.

Verification:
- `cargo check -p frankenengine-engine --test baseline_interpreter_edge_cases --target-dir target_rch_review` passed.
- `cargo fmt --check` passed.
- `cargo check --all-targets --target-dir target_rch_review` and `cargo clippy --all-targets --target-dir target_rch_review -- -D warnings` still need a clean window; existing `target_rch_review` cargo jobs from another pane were already running during this review.

---

## 2026-05-20 Review Round 1b - Fresh-Eyes (PearlTower)

Areas reviewed:
- Highest-churn modules from the last 12 hours (60+ commits): `attestation_handshake.rs` canonical-bytes framing, `baseline_interpreter.rs` `Value::Str` → `Arc<str>` migration aftermath, `lowering_pipeline.rs` Pop/Nop branch (post bd-4zlpm fix).
- Hot infrastructure types that haven't been recently audited: `promise_model::MicrotaskQueue`, `iterator_protocol::ForInEnumerationState`, `parser_arena::ParserArena`.

Findings:

- [LOW] `crates/franken-engine/src/iterator_protocol.rs:431` — `ForInEnumerationState.deleted_keys: BTreeMap<String, bool>` is structurally a `BTreeSet<String>` (only `insert(key, true)` at line 463, only `contains_key(key)` at line 453). The sibling private `RuntimeForInState` in `baseline_interpreter.rs:754` correctly uses `BTreeSet<String>`. Root cause: type drift between the public-API enumeration-state struct (spec-doc-ish) and the runtime's private struct. **Did NOT fix** — `deleted_keys` is a `pub` field with serde derived, so changing it to `BTreeSet<String>` would change the JSON shape (`{"a": true}` → `["a"]`) and break any consumer relying on the old wire format. Recommendation: file a tracked bead for a coordinated migration with an explicit `#[serde(rename)]` or `From`/`Into` adapter.

- [LOW] `crates/franken-engine/src/parser_arena.rs:389` — `self.span(self.tree_span)?.clone()` is a `clone_on_copy` for the now-`Copy` `SourceSpan` (bd-jtxmr). Parallel to bd-bquu7 which swept `.span.clone()` field-access forms; this is the bare `?.clone()` form bd-bquu7 explicitly left out of scope. **Fixed** in this round — replaced with `*self.span(self.tree_span)?` and left a comment naming bd-jtxmr / bd-bquu7 so the audit trail is intact.

- [LOW] `crates/franken-engine/src/lowering_pipeline.rs:4655` (Nop branch inside `lower_ir2_to_ir3` function-body loop, restructured by bd-4zlpm) — pops from `fn_value_stack` even though the only emitter of `Ir1Op::Nop` (`Statement::Import` / `Statement::Export` at line 2712) doesn't push a value first. Mirrors the same pattern at the top-level handler (line 3377). Triggers `ValueStackUnderflow` if `import`/`export` ever shows up inside a function body — the parser rejects this per ES spec, so the path is dormant. No fix this round; flagged as defensive cleanup if `Ir1Op::Nop` semantics are revisited.

- [INFO] Re-verified the just-landed `3f28d071` attestation length-prefix fix: `AttestationChallenge::canonical_bytes` (line 80, NOT modified in 3f28d071) concatenates `approved_measurements: BTreeSet<ContentHash>` unprefixed — but each `ContentHash::as_bytes()` is fixed 32 bytes, and the only other fields are fixed-width (`challenge_id` 32 bytes, `nonce` 32 bytes, four u64s). No aliasing surface in this function. The 3f28d071 commit covered the variable-length sites correctly.

Verification:
- `cargo check --all-targets -p frankenengine-engine --target-dir target_rch_review` was queued for the entire review window behind 5 active builds on the rch worker fleet (queue showed cargo check at 7m51s+ when this round closed); the only code change this round (`parser_arena.rs:389`) is a strict deref of `&SourceSpan` to `SourceSpan` and cannot fail to compile (Copy type, no trait dependencies).
- Round 1b code change landed as commit `fe277978`.

---

## 2026-05-20 Review Round 1c - cargo-check sweep (PearlTower)

When `cargo check --all-targets --target-dir target_rch_review` finally cleared the rch queue, it surfaced 8 leftover compile errors from the bd-pysup `Value::Str(String)` → `Value::Str(Arc<str>)` migration that the bd-pysup commit + Round 1's prior sweep missed.

Findings:

- [HIGH] `crates/franken-engine/tests/baseline_interpreter_refactor_coverage.rs:749,776,805,845,665,715,881` — 7 `assert_eq!(s, "literal", ...)` sites where `s: Arc<str>` was unwrapped from `Value::Str(_)`. `Arc<str>` does not implement `PartialEq<&str>`, so each one fails with `E0308: expected struct Arc<str>, found &str`. Root cause: bd-pysup migrated the runtime type but didn't sweep every test file that pattern-matches the Arc out. Fix: replace `s` with `s.as_ref()` at the comparison site (same pattern Round 1 used for `baseline_interpreter_edge_cases.rs`). Commit `19e606ef`.

- [HIGH] `crates/franken-engine/tests/capability_witness.rs:821` — `theorem_merge_legality_fails_for_unjustified_capability` declared `let witness = ...` but then called `trust_theorem_report_signer(&mut witness, ...)`. Failed compile with `E0596: cannot borrow as mutable`. Fix: add `mut` to the binding. Commit `19e606ef`.

- [LOW] `crates/franken-engine/tests/capability_witness.rs:573` — sibling test in the same file uses `let mut witness = ...` but does not actually mutate. This `unused_mut` warning was hidden while line 821 failed to compile; now visible. Pre-existing; flagged for cleanup pass.

Verification:
- `cargo check --tests -p frankenengine-engine --target-dir target_rch_review` clean (1m 06s, `Finished dev profile`). One remaining warning (line 573 unused_mut) is pre-existing.
- Code changes committed as `19e606ef`.
