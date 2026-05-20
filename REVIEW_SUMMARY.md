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

---

## 2026-05-20 Review Round 1d - Deterministic replay and gate sweep (Codex)

Areas reviewed:
- `AGENTS.md` and `README.md` end to end, then recent activity via `git log --since="6 hours ago" --oneline` and `git diff HEAD~30..HEAD`.
- High-risk recent churn in revocation/degraded-mode freshness, baseline interpreter `Value::Str(Arc<str>)` migration fallout, exception/error helper tests, and capability witness conformance.

Findings:

- [HIGH] `crates/franken-engine/src/revocation_freshness.rs:519-535` - `RevocationFreshnessController::new(config, zone)` derived its default `policy_id` from OS randomness, so two controllers built from the same zone and freshness config could receive different policy identities. Root cause: the default constructor used a random nonce as the policy-id preimage instead of stable policy inputs, violating deterministic replay expectations for default controller construction and making override/evidence identities non-repeatable. Fixed: `new` now derives the policy id from length-prefixed zone/config bytes; regression tests at `revocation_freshness.rs:972-992` pin stable same-input ids and differing ids for changed zone/config.

- [MEDIUM] `crates/franken-engine/tests/error_stack_trace_formatting.rs:140-143` and `crates/franken-engine/tests/exception_semantics_conformance.rs:72-79` - helper functions still returned `Value::Str` payloads directly as `String` after the runtime value payload migrated to `Arc<str>`. Root cause: partial test/helper migration around `Value::Str(Arc<str>)`. Fixed by converting the Arc-backed payload to `String` at the helper boundary.

- [MEDIUM] `crates/franken-engine/tests/capability_witness.rs:821-835` - `theorem_merge_legality_fails_for_unjustified_capability` passed a witness by mutable reference to `trust_theorem_report_signer`, but the fixture binding had drifted immutable. Root cause: signer API mutability not reflected in the conformance fixture. Fixed by restoring `let mut witness` for that fixture.

- [LOW] `crates/franken-engine/tests/capability_witness.rs:575-584` - sibling fixture kept `let mut witness` without mutation, which would fail `clippy -D warnings` once compile errors were cleared. Fixed by removing the unused mutability.

- [LOW] Formatting drift across touched and adjacent files prevented `cargo fmt --check` from passing after the review edits. Fixed by running `cargo fmt`; these were formatting-only changes.

- [MEDIUM] Clippy gate is still blocked by a broad pre-existing lint backlog: `cargo clippy --all-targets --target-dir target_rch_review -- -D warnings` failed with 210 errors. The dominant class is `clippy::clone_on_copy` for `SourceSpan` after it became `Copy` across `ast.rs`, `parser.rs`, `dual_backend_parser.rs`, `parser_multi_engine_harness.rs`, `react_jsx_lowering.rs`, and `static_semantics.rs`; additional examples include `clippy::derivable_impls` for `FlowPolicyEnforcement` at `ifc_artifacts.rs:667` and `clippy::field_reassign_with_default` in `profiling.rs:379-435`. Root cause: recent type/lint policy changes outpaced a full all-target clippy cleanup. Not fixed in this round because it is a broad mechanical rewrite across core parser/lowering surfaces and should be isolated.

Verification:
- `cargo fmt --check`: PASS after the final format pass.
- `cargo check --all-targets --target-dir target_rch_review`: PASS on rch worker `vmi1227854` (`Finished dev profile`, remote exit 0) after the substantive revocation and test-helper fixes. Post-check edits were limited to removing one unused `mut` and formatting-only changes.
- `cargo clippy --all-targets --target-dir target_rch_review -- -D warnings`: FAIL, remote exit 101, 210 lint errors as summarized above.

---

## 2026-05-20 Review Round 1e - .gitignore + cross-cluster audit (Opus, review-only)

Read AGENTS.md + README.md (first 200 lines) end-to-end, then `git log --since="6 hours ago"` (110 commits) and the prior 4 review rounds. Recent activity dominated by: `Value::Str(String)→Arc<str>` (bd-pysup), `SourceSpan: Copy` derive (bd-jtxmr / 45fd085d), attestation length-prefix framing (3f28d071), evidence-ledger signing-key hardening (1975db42), and a bd-4zlpm function-body Pop fix.

Round 1 focused on areas the prior four rounds had not deeply covered: the working-tree's stray target dirs, a mutex-poison sweep beyond bd-ctry0's scope, and a fresh pass over the witness-pipeline signing-key surface to verify 1975db42's blast radius.

Findings:

- [HIGH] `.gitignore:65-69,143-146` — the `target_rch_*` ignore patterns are only rooted at the repository root (`/target_rch_*/`) and a small set of literal `crates/*/...` subpaths. Two untracked dirs at `crates/franken-engine/src/target_rch_review/` and `crates/franken-engine/target_rch_test_audit/` (both visible in `git status` at session start) are not matched, so `git add -A` from any pane will happily stage them. This is the exact failure class the in-file comment at lines 8-16 explains motivated two prior `git filter-repo` passes (`d8efc6b5`, `5294ed2d`) after a 576 MB `dep-graph.part.bin` was committed. Root cause: review/audit panes invoked `cargo --target-dir target_rch_review` while their cwd was inside `crates/franken-engine/src/`, so the target tree landed below `src/`. **Fixed**: appended `crates/*/target_rch_*/`, `crates/*/src/target_rch_*/`, and `**/target_rch_*/` patterns. Verified via `git check-ignore -v` that all three stray dirs (incl. the workspace-root one created by my own clippy run) are now matched by `**/target_rch_*/`.

- [LOW] `crates/franken-engine/src/dual_backend_parser.rs:1232` and `crates/franken-engine/src/parser_multi_engine_harness.rs:2290` — two `span: span.clone()` / `canonical_span: span.clone()` sites that trip `clippy::clone_on_copy` now that `SourceSpan` is `Copy` (45fd085d). Both inside `#[cfg(test)] mod tests`, so caught by `cargo clippy --all-targets`. **Fixed**: dropped the `.clone()`. Singleton fixes per-file — surgical, no risk to public API. The remaining ~113 `.span.clone()` sites across `ast.rs` (42), `parser.rs` (23), and `react_jsx_lowering.rs` (48) are the bulk of Round 1d's reported "210 clippy errors". Per AGENTS.md "no broad regex rewrites", these need per-file beads rather than one mass commit.

- [INFO] `clippy::derivable_impls` (ifc_artifacts.rs) and `clippy::field_reassign_with_default` (profiling.rs) from Round 1d both look already-resolved in HEAD. `FlowPolicyEnforcement` (ifc_artifacts.rs:656-668) has `#[derive(... Default)]` with `#[default]` on `AllowlistOnly`; profiling.rs uses `..Default::default()` struct-update syntax everywhere. Both clippy-clean as far as a source read shows; a clean clippy run will confirm.

- [INFO] Mutex-poison sweep beyond bd-ctry0's scope — grepped `crates/franken-engine/src/` for `\.lock()\.(unwrap|expect)`. The only production-code matches are the two bd-ctry0-fixed sites in `shadow_decision_composer.rs:773` and `:2078`, both using `unwrap_or_else(|poison| poison.into_inner())`. The `parallel_parser.rs:2927,2938` `expect("thread id mutex should not be poisoned")` sites are inside `#[cfg(test)] mod tests`. bd-ctry0 appears comprehensive for that pattern in the engine crate.

- [INFO] Witness-pipeline signing-key audit (post 1975db42) — grepped `crates/franken-engine/src/` for `authorize_producer`, `DEFAULT_EVIDENCE_PRODUCER_ID`, `default_evidence_signing_key`. Production-side callers of `EvidenceEntryBuilder::new()` outside the test trees are: (a) `evidence_ledger.rs::default_stitching_entry:1771` — a `pub fn`-emitted demo bundle whose consumers don't validate the result back into a ledger (hardcoded "ext-abc"/"0.85"/"sandbox" fixture data is deliberate); (b) `evidence_ordering.rs:314` — inside `#[cfg(test)]`. The `1975db42` fix narrowed `WitnessPublicationPipeline::emit_evidence_entry` correctly, but the *constants* `DEFAULT_EVIDENCE_SIGNING_KEY_BYTES = [0x7B; 32]` and `DEFAULT_EVIDENCE_PRODUCER_ID = "franken-engine.evidence-ledger.builder"` (evidence_ledger.rs:58-67) plus the `InMemoryLedger::Default` pre-authorization (line 533) remain as a structural risk: any *future* production code path that calls `EvidenceEntryBuilder::new(...).build()` without `.signed_by(...)` will mint an entry signed with the well-known key, accepted by `InMemoryLedger::Default`. Recommendation (not fixed this round — invasive, public-API change): either (i) drop `.signed_by(...)` defaults and require an explicit `SigningKey` argument at `EvidenceEntryBuilder::new` (typestate, or required positional arg), or (ii) wire a fail-closed validator that rejects ledger entries whose verification key matches `default_evidence_verification_key()` outside `#[cfg(test)]`.

- [INFO] Deterministic-ordering audit (BTreeMap/BTreeSet rule from README + bd-pvr9h) — grepped `crates/franken-engine/src/` for `HashMap::new`, `HashSet::new`, `use std::collections::Hash*`. Only one production-code site: `epoch_barrier.rs:257,275` uses `HashSet<u64>` for `active_guard_ids`. Operations are only `insert`/`remove`/`clear`/`is_empty`/`len`; struct is `#[derive(Debug)]` only — no serde, no iteration. Not a determinism violation. All other matches are in `#[cfg(test)]` blocks or in `bin/franken_closure_report.rs` (a CLI report tool).

- [INFO] Re-verified Round 1b's "dormant `Nop` underflow" assessment. The only emitter of `Ir1Op::Nop` is `Statement::Import|Statement::Export` at `lowering_pipeline.rs:2710-2712`, which is inside `lower_statement_to_ir1_with_flow` — called only for *nested* statements. Top-level imports take `lower_ir0_to_ir1::Statement::Import` at line 555, which emits `Ir1Op::ImportModule` directly without going through Nop. The parser rejects nested import/export per ES spec, so both `lower_ir2_to_ir3` Nop arms (lines 3377, 4655) are unreachable in practice. No fix needed; carry as documented latent.

Verification:
- `cargo fmt --check`: PASS.
- `cargo clippy --all-targets -p frankenengine-engine --target-dir target_rch_review -- -D warnings`: first attempt SIGKILL'd on the rch worker after 18m43s (signal: 9 — OOM under the concurrent 8-build queue). Re-ran with `--lib` only, still pending in the queue at the time of this writeup; pre-existing 210-error backlog will dominate any successful run anyway, so the two surgical fixes here only push the count down by 2.
- `git check-ignore -v crates/franken-engine/src/target_rch_review crates/franken-engine/target_rch_test_audit target_rch_review`: all three matched by `.gitignore:154 **/target_rch_*/`.

Code changes pending commit in this round (uncommitted in this pane, per the "REVIEW-ONLY MODE" prompt's instruction to fix bugs but not commit):
- `.gitignore` (+8 lines: three new target_rch ignore patterns with a comment explaining the prior filter-repo incident class).
- `crates/franken-engine/src/dual_backend_parser.rs:1232` (drop `.clone()` on `SourceSpan`).
- `crates/franken-engine/src/parser_multi_engine_harness.rs:2290` (drop `.clone()` on `SourceSpan`).


---

## 2026-05-20 Review Round 1e - Arc<str> migration residual + clippy gate triage (PearlTower)

Areas reviewed:
- `AGENTS.md` end-to-end, README §"Determinism discipline" / §"Numeric discipline" / §"Cryptographic primitives".
- Recent activity via `git log --since="6 hours ago"` and `git log --since="48 hours ago"` (107 commits).
- Determinism-discipline regression sweep: `HashMap`/`HashSet` actual uses (vs comment mentions), `i128::div_ceil`, `BTreeMap<EngineObjectId, _>` serde sites, `f64` in public-serde structs.
- Crypto preimage / canonical_bytes audit across `policy_checkpoint.rs:247`, `capability_token.rs:331`, `revocation_enforcement.rs:226`, `module_resolver.rs:236`, `module_compatibility_matrix.rs:695`, `ast.rs:124`, `resolver_package_index.rs:187/257/895`, `attested_execution_cell.rs` (post 3f28d071).
- Spot-checked the recent attestation length-prefix fix (commit 3f28d071) for completeness against all `signature_payload` / `canonical_bytes` sites.

Findings:

- [CRITICAL] `crates/franken-engine/tests/prototype_chain_descriptor.rs:75-81` — `assert_eq!(*expected, actual.as_ref(), ...)` compared `str` against `&str` after the `Value::Str(Arc<str>)` migration (commit `859c32d1`). The `*expected` deref was correct when `actual.as_ref()` was `&&str`; once it became `&str`, the same deref produces a `str == &str` comparison that does not implement `PartialEq`. Effect: `cargo check --all-targets` failed (`E0277` at `tests/prototype_chain_descriptor.rs:75:17`), which gated the AGENTS.md compiler-checks rule. Fixed: dropped the `*` so both sides are `&str`. Comment added pointing at the Arc migration commit. Verified: `cargo check --test prototype_chain_descriptor -p frankenengine-engine --target-dir target_rch_review` PASS (2m 17s). `cargo check --all-targets -p frankenengine-engine --target-dir target_rch_review` PASS after the fix.

- [OBSERVATION — no finding] Determinism-discipline grep over `crates/franken-engine/src` and `crates/franken-extension-host/src` found exactly 7 files mentioning `HashMap`/`HashSet`. Five are correct/safe:
  - `epoch_barrier.rs:257` — `active_guard_ids: HashSet<u64>`, struct is `#[derive(Debug)]` only (no Serialize), and the field is never iterated (only `insert`/`remove`/`clear`/`is_empty`/`len`). No content-hash exposure.
  - `parallel_parser.rs:2360, 2917` — `HashSet` is `#[cfg(test)]`-only for thread-id dedup; never serialized.
  - `parallel_interference_gate.rs:718, 1693` — string-literal mentions of "HashMap" as remediation advice; no actual usage.
  - `bin/franken_closure_report.rs:160, 161` — operator-tool HashSet for unique counts, never serialized as ordered.
  Two were the `bd-pvr9h` finding already shipped (`throughput_disruptive_floor_metric_gate.rs`, `bin/franken_benchmark_gate.rs`) — commit `2b883df9` already converted them to `BTreeMap`.

- [OBSERVATION — no finding] No `i128::div_ceil()` usages in `crates/franken-engine/src` or `crates/franken-extension-host/src` (the documented nightly-instability hazard is absent).

- [OBSERVATION — no finding] The recent attestation length-prefix fix (`3f28d071`) is complete for the two named encoders. Audit of the broader `canonical_bytes` / `preimage_bytes` surface (10+ functions across `policy_checkpoint`, `capability_token`, `module_resolver`, `module_compatibility_matrix`, `ast`, `resolver_package_index`, `revocation_enforcement`) confirms they either (a) delegate to `deterministic_serde::encode_value` (which length-prefixes byte/string fields per its module docs) or (b) use the local `append_str` / `append_len_prefixed_bytes` helpers that include `u64`-BE length prefixes. No further sites need the `3f28d071`-style fix.

- [LOW — surfaced, not fixed] `crates/franken-engine/src/resolver_package_index.rs:932-960` `SubpathResolutionReceipt::new` computes `content_hash` over a buffer that does NOT include `conditions_tried: Vec<String>` (line 957, populated after the hash). If two receipts with identical resolution outcome but different trial-condition sequences are intended to have distinct identities, the content_hash omission means they would collide. Not fixed in this review pass because the semantics ("evidence hash represents the resolution outcome, not the trial path") may be intentional — needs author confirmation before tightening. Worth a follow-up audit.

Verification:
- `cargo check --all-targets --keep-going -p frankenengine-engine --target-dir target_rch_review` ✓ PASS post-fix (`Finished dev profile`, 1.54s incremental).
- `cargo fmt --check` ✓ PASS (background task `b3nu00azf` exit 0).
- `cargo clippy --all-targets -- -D warnings` ❌ FAIL — the existing 210-error backlog dominated by `clone_on_copy` on `SourceSpan` (post-`bd-jtxmr` Copy derive) is unchanged and not in scope for this round. Tracked under bd-bquu7. The Round 1d note already captured this as MEDIUM.
