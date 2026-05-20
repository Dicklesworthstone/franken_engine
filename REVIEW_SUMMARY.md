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

---

## 2026-05-20 Review Round 2 - P3 Cross-Review (PearlTower)

Focused on other agents' security-cluster commits: 61d4fbed (evidence ledger signing), 95f12ab2 (revocation epoch binding), 29f6b85e (capability witness keygen), cb84b29d (FlowPolicy enforcement), and the recent perf/migration cluster (9e55a0fe Ir3 profiling, a86d8a01 scope name borrow, 45fd085d SourceSpan Copy, 1c8e9b4c lowering pop fix).

Findings:

- [HIGH] `crates/franken-engine/src/evidence_ledger.rs:58-66` + `crates/franken-engine/src/capability_witness.rs:3397,3920` — **Evidence-ledger default signing key was a public constant**. The 61d4fbed commit added `EvidenceSignatureEnvelope` and a `validate_entry` path that requires every emitted entry to be signed by an authorized producer, but `EvidenceEntryBuilder::new()` defaults to `producer_id = DEFAULT_EVIDENCE_PRODUCER_ID = "franken-engine.evidence-ledger.builder"` + `signing_key = DEFAULT_EVIDENCE_SIGNING_KEY_BYTES = [0x7B; 32]`, and `InMemoryLedger::new()` pre-authorizes that exact pair (lines 526-538). `WitnessPublicationPipeline::emit_evidence_entry` (line 3917+) never overrides `.signed_by(...)`, so production-side witness emission was relying entirely on the well-known constant key. Any caller anywhere in the workspace could mint entries that pass the default ledger's validation — i.e. the bd-i7ke2 "require signed ledger entries" guarantee was structurally present but provided zero origin authentication for the pipeline path. **Fixed** in commit `1975db42`: `WitnessPublicationPipeline::new` now derives a per-policy producer id (`franken-engine.witness-pipeline:<policy_id>`) and registers the pipeline's real `head_signing_key.verification_key()` for it; `emit_evidence_entry` attaches `.signed_by(producer_id, self.head_signing_key.clone())` so emissions are signed by the actual head key the pipeline already uses for tree-head signatures. Forging entries that pass validation now requires possessing the pipeline's head key.

- [HIGH] `crates/franken-engine/tests/capability_witness.rs:171,198` — Concurrent (likely `cargo clippy --fix`) sweep removed `mut` from two `let witness = WitnessBuilder::new(...)` bindings, but lines 189/214 still pass `&mut witness` to `apply_passing_promotion_theorems`. Broke `cargo check --tests`. **Fixed** in commit `1975db42`: restored `let mut witness` at both sites with a comment naming the `&mut`-taking call line below so the next clippy sweep doesn't re-break it.

- [MEDIUM] `crates/franken-engine/src/profiling.rs:139,182,291` — `instruction_name()` uses `format!("{:?}", instruction)` to extract a variant name, allocating a full Debug-rendered String of the instruction's contents (incl. possibly several fields), then truncating to before `" {"` or `"("`. Called twice per executed instruction when profiling is on (record_instruction + record_instruction_time). The execution_orchestrator already has a full `instruction_mnemonic` match returning `&'static str` (line 1739+) — the profiler could share that or use the same shape. **Not fixed** this round: the simple-looking change requires a ~80-arm match touching the same enum many concurrent perf/migration commits already edit; lower risk to file as follow-up than to land mid-stream. Filed in REVIEW_SUMMARY for owner pickup.

- [LOW] `crates/franken-engine/src/iterator_protocol.rs:443` (carried from Round 1b) — `deleted_keys: BTreeMap<String, bool>` is structurally a `BTreeSet<String>` (only `(k, true)` insert + `contains_key` reads). Sibling `RuntimeForInState` in `baseline_interpreter.rs:754` already uses `BTreeSet<String>` correctly. Still not fixed — `pub` field + serde, breaking change.

- [INFO] `crates/franken-engine/src/revocation_chain.rs::verify_head_epoch_freshness` (95f12ab2) — `head.epoch_id.as_u64() + MAX_REVOCATION_HEAD_EPOCH_STALENESS(=0) < current_epoch.as_u64()` rejects PAST-epoch heads but accepts FUTURE-epoch heads. Intentional given the threat model (a forged future-epoch head still needs a valid signature, and authorized_head_keys gates that); not a finding, but documented here so a future epoch-binding tightening doesn't have to re-derive the rationale.

- [INFO] `crates/franken-engine/src/ifc_artifacts.rs::FlowPolicy::is_flow_allowed_with_enforcement` (cb84b29d) — `pub` API lets a consumer override the policy author's chosen `enforcement_mode` at the call site (e.g. pass `LatticeOpen` against an `AllowlistOnly` policy). Reviewed and confirmed this is by design — different surfaces within the engine have different enforcement needs. The default-fail-closed serde migration test pins the security-relevant case.

- [INFO] `crates/franken-engine/src/baseline_interpreter.rs:4656` — per-dispatch `.clone()` of `Ir3Instruction` remains. Blocked from `Copy` derive because `Ir3Instruction::HostCall` owns a `CapabilityTag(String)`. Documented in bd-9tcjr; the secondary profiling clone is already removed.

Verification:
- `cargo check --tests -p frankenengine-engine --target-dir target_rch_review` clean (14.83s, `Finished dev profile`) — verifies both the security fix and the restored `let mut` lines.
- Production code change committed as `1975db42` (security hardening) + `b488af74` (Round 1c notes).
