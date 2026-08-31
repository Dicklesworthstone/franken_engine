# Contributing to FrankenEngine

FrankenEngine is a native Rust execution substrate for adversarial JavaScript/TypeScript extension workloads. Changes are accepted only when the implementation, failure semantics, focused verification, tracker state, and published claim boundary agree.

## Read This First

Read these in order before editing:

1. `AGENTS.md` — binding repository rules.
2. `README.md` — product surface and current bounded claims.
3. `docs/ARCHITECTURE_OVERVIEW.md` — the implemented call graph and architectural boundaries.
4. `docs/RUNTIME_CHARTER.md` — constitutional runtime constraints.
5. The route emitted for the files you plan to touch:

```bash
python3 scripts/agent_route.py --path crates/franken-engine/src/lowering_pipeline.rs
python3 scripts/agent_route.py --changed HEAD~1 --include-worktree
python3 scripts/agent_route.py --claim FE-CLAIM-011 --format commands
```

`docs/agent_change_routes_v1.json` is the machine-readable ownership map behind that command. It binds paths to semantic anchors, governing documents, focused checks, downstream truth artifacts, claim IDs, tracker search terms, and collision risk. Keep it current when a new subsystem or source-of-truth file appears.

## The Execution Model

The core path is:

```text
JavaScript/TypeScript source
        |
        v
parser.rs + ast.rs
        |
        v
Ir0Module -> Ir1Module -> Ir2Module -> Ir3Module
        lowering_pipeline.rs
        |
        v
execution_orchestrator.rs
        |
        v
LaneRouter -> InterpreterCore
        baseline_interpreter.rs
        |
        v
ExecutionResult + nondeterminism trace + evidence + IR4/witness artifacts
```

The orchestrator owns prepare, guard, execute, containment, and evidence phases. The baseline interpreter is the production execution core reached by the named lanes. IR4 is a post-execution witness surface, not another executable tier. Compatibility belongs above the core; dependency direction remains `franken_node -> franken_engine`.

`crates/franken-extension-host` is a separate signed-manifest and extension-policy boundary. Do not copy engine semantics into it or introduce a reverse dependency into the core.

## Before You Claim Work

This repository uses `br` for beads. The durable JSONL file is a mirror of the local tracker database, not a safe substitute for tracker commands.

```bash
br ready
br show <bead-id>
br update <bead-id> --status in_progress
```

Before claiming:

- inspect dependencies and blockers;
- inspect recent commits and tracker activity;
- inspect `git log -8 --oneline -- <path>` for every hotspot you expect to edit;
- confirm another agent is not already changing the same semantic boundary;
- prefer the smallest unblocked bead that unlocks downstream work.

After a verified implementation:

```bash
br close <bead-id> --reason "implemented and verified: <concise evidence>"
br sync --flush-only
```

Do not mark a bead complete from code shape alone. A security, performance, replay, or evidence task is complete only when its adversarial/failure path and preserved proof surface are also correct.

## Direct-to-Main Discipline

The repository is developed incrementally on `main`.

- Re-read the target file from current `main` immediately before each write.
- Keep each commit to one coherent semantic change.
- Commit tests or executable guards next to the behavior they protect.
- Do not accumulate a large private patch and land it as one batch.
- Do not rewrite, revert, or “clean up” unrelated concurrent work.
- Never delete files without explicit permission.
- Never run destructive cleanup such as `git reset --hard`, `git clean`, or `cargo clean`.
- Use a unique `CARGO_TARGET_DIR` when build isolation is needed.

A good sequence is:

```text
claim bead -> inspect route/history -> implement narrow delta -> run focused proof
-> commit -> add adversarial/drift guard -> commit -> update truth artifacts
-> commit -> close/sync bead
```

## Build Modes

The root workspace uses Rust nightly and edition 2024.

Standalone engine work:

```bash
CARGO_TARGET_DIR=/tmp/franken_engine_target_<agent> \
CARGO_INCREMENTAL=0 \
cargo check --release --no-default-features -p frankenengine-engine --bin frankenctl
```

Default/full-integration work may use sibling projects under `/dp`. Do not introduce a local replacement for a stronger sibling substrate without explicit approval. Do not add a binding-led V8, QuickJS, or equivalent core path.

## Validation Ladder

Run the smallest command that actually proves the changed invariant, then expand only as the boundary requires.

### 1. Cheap syntax and contract checks

```bash
python3 -m py_compile <changed-python-files>
bash -n <changed-shell-files>
python3 scripts/agent_route.py --check
cargo fmt --check
```

### 2. Focused semantic checks

Use the commands returned by `scripts/agent_route.py`. Examples:

```bash
cargo test -p frankenengine-engine lowering --lib
cargo test -p frankenengine-engine declassification_pipeline --lib
./scripts/run_lowering_gap_truth_invariant.sh ci
./scripts/run_replay_coverage_metric_gate.sh ci
```

### 3. Negative or ambiguity drills

Every fail-closed boundary needs a test that proves the guard can fail. Examples include:

- malformed or missing runtime output;
- replay or nonce reuse;
- conflicting identities or schema versions;
- fixture-only evidence presented as observed evidence;
- a drifted manifest or documentation mirror;
- timeout/crash/parser failure that must not count as containment.

### 4. Crate-level gates

```bash
cargo check -p frankenengine-engine
cargo clippy -p frankenengine-engine --all-targets -- -D warnings
cargo test -p frankenengine-engine
cargo fmt --check
```

Use remote compilation only when the local environment provides it and the command is genuinely heavy. Preserve the exact command, revision, exit status, and relevant artifacts in the bead or evidence bundle.

## Semantic Rules

### Determinism

- Use `BTreeMap`/`BTreeSet` when iteration order reaches hashes, serialization, replay, or user-visible output.
- Sort vectors before canonical hashing.
- Length-prefix variable-length fields.
- Distinguish `None` from `Some(empty)` in preimages.
- Use fixed-point millionths for hashed/public ratios; do not put platform-sensitive floating-point values in canonical artifacts.
- Make overflow behavior explicit with checked, saturating, or wrapping arithmetic.

### Safety and authority

- Production engine source must remain unsafe-free; do not broaden unsafe usage.
- Every host effect must pass the appropriate capability and IFC boundary.
- A declassification receipt must bind every identity needed to justify its claims: policy, route, sink, site, transform, output, replay identity, and cryptographic key/nonce identity where applicable.
- Absence of evidence is never evidence of containment, authorization, replay success, or comparator success.
- Unknown, blocked, degraded, refused, fixture-only, and observed are distinct states.

### Error behavior

Prefer typed refusal over fabricated compatibility. A parser error, runtime crash, malformed report, missing comparator, or timeout must remain visible as its own outcome. Do not collapse it into a favorable boolean.

### Optimization

An optimization is incomplete without:

- semantic parity on the executed path;
- preserved IFC/capability/replay/evidence behavior;
- an adversarial or rollback guard;
- a reproducible measurement against the correct lifecycle;
- countermetrics for memory, tail latency, and failure behavior where relevant.

A plan, provenance record, quickening candidate, or AOT artifact is not machine-code execution.

## Parser and Language-Surface Work

For a new or repaired construct, trace the entire tower:

```text
parser -> AST -> IR0 -> IR1 -> IR2 -> IR3 -> interpreter
       -> error semantics -> replay/evidence -> gap inventories
```

Update both `parser_gap_inventory.rs` and `lowering_gap_inventory.rs` when their truth changes. “Parsed,” “lowered,” and “execution-ready” are separate states. Refusal is not implementation.

Do not make broad edits to `lowering_pipeline.rs` or `baseline_interpreter.rs`. They are critical shared hotspots. Isolate one construct or invariant, use narrow helpers, and commit before beginning the next semantic unit.

## Evidence and Claim Work

The authoritative claim state is `docs/claim_to_proof_matrix_v1.json`. Its human-readable and crate-local mirrors are:

- `docs/CLAIM_TO_PROOF_MATRIX_V1.md`
- `crates/franken-engine/docs/claim_to_proof_matrix_v1.json`

Update producer, negative drill, canonical JSON, mirrors, and README wording together. Keep a claim `TARGET` or `HYPOTHESIS` until a fresh real proof bundle exists. A gate implementation alone is not an observed measurement.

For cross-runtime metrics:

- execute every comparator on the same declared scenario/workload;
- bind executable identity/version and hash;
- preserve stdout, stderr, exit status, duration, and disposition source;
- prove output equivalence before comparing performance;
- refuse malformed, ambiguous, missing, or crashed lanes;
- never substitute hardcoded comparator outcomes.

Run:

```bash
./scripts/run_claim_to_proof_matrix_gate.sh ci
```

## Tests

Add the tests needed to prove the invariant; do not optimize for a blanket per-file count.

Strong coverage normally includes:

- focused unit tests for local state transitions;
- an integration test for the cross-module contract;
- at least one negative/adversarial case;
- deterministic serialization/hash/replay checks for persisted types;
- a drift guard when prose, inventories, schemas, or generated mirrors can diverge.

Fixture-only tests are useful, but their outputs must stay labeled as fixtures and must not back an observed product claim.

## Adding a Module

Before creating a file, confirm the behavior does not belong in an existing module.

When a new module is justified:

1. use a semantic name; do not create `_v2`, `_new`, `_improved`, or similar parallel implementations;
2. register it in `lib.rs` in the existing ordering convention;
3. add focused tests and a cross-module proof where needed;
4. add the path to `docs/agent_change_routes_v1.json`;
5. update architecture inventory/truth surfaces that enumerate modules;
6. run route validation and the relevant crate gates.

## Commit Messages

Use a conventional, specific subject and include the bead ID when the commit advances one:

```text
fix(ifc): bind nonce uniqueness to key identity (bd-...)
test(replay): reject cross-epoch witness reuse (bd-...)
docs(agent): route module-loader changes through lifecycle checks
```

The commit subject should describe the invariant changed, not merely the file touched.

## Definition of Done

A change is done when:

- the live behavior is implemented;
- the unfavorable and ambiguous paths are explicit;
- focused tests and negative drills pass;
- broader checks appropriate to the boundary pass;
- bead status and notes reflect reality;
- generated inventories and mirrors agree;
- claim wording does not exceed the preserved evidence;
- commits are small enough to bisect and safe for concurrent agents.
