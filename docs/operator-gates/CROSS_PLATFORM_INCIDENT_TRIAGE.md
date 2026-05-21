# Cross-Platform Incident Triage

Operator runbook for cross-platform `ContentHash` divergence: how to
interpret it, how to decide whether it is a determinism bug in
FrankenEngine itself or an environmental issue with the build/runtime
worker, and how to file a bead for cross-platform regressions.

## Bead anchors

- Track parent: **bd-cixqu.11** (Track K — multi-platform matrix
  Linux/macOS/Windows × x64/arm64).
- This document: **bd-cixqu.11.6** (K.6 operator-runbook).
- Determinism contract: README §"Determinism discipline" and §"Numeric
  Discipline Deep-Dive".
- Content-hash code: `crates/franken-engine/src/hash_tiers.rs` +
  `crates/franken-engine/src/deterministic_serde.rs`.

## What "content-hash divergence" means

The reproducibility-bundle contract requires that **two builds on
different platforms produce identical `ContentHash` values for the same
input**. Divergence between platforms is the central signal Track K
gates against: if a workload, an evidence record, or a proof bundle
hashes to value `H₁` on Linux/x64 and `H₂` on macOS/arm64, the audit
trail says the two builds did **different work** even when they were
asked to do the same work.

Cross-platform CI emits a divergence report under
`artifacts/rgc_cross_platform_matrix/<run>/` whose `divergence_log.jsonl`
lists every (input, platform-a-hash, platform-b-hash) triple where the
hashes differ. That file is the starting point for triage.

## Step 1 — Confirm the divergence is real

Before declaring a determinism bug, confirm the inputs are actually
identical:

1. **Input hash check.** Each entry in `divergence_log.jsonl` includes
   the input content-hash, computed by the worker BEFORE the workload
   ran. The two platforms must agree on the input hash. If they do
   not, the inputs themselves differ (filesystem normalisation, line
   endings, locale-dependent file walk order, etc.) and you have an
   *input* problem, not a *runtime* problem.
2. **Toolchain version check.** The matrix worker records
   `rustc --version` and the Cargo lockfile hash in
   `worker_facts.json`. If they differ between the two platforms the
   reproducibility envelope is already broken before any FrankenEngine
   code runs.
3. **Re-run on the failing platform with `RGC_REPLAY_RECORD=1`.** This
   captures the per-step inputs/outputs the run actually used. A
   second-run divergence different from the first is not a reproducible
   bug; it is a non-determinism source you need to track down before
   anything else.

If steps 1–3 all show identical inputs and matching toolchain facts
and the divergence reproduces deterministically, proceed to Step 2.

## Step 2 — Decide: determinism bug or worker-environment issue

The decision flow is a small tree. Walk it in order; stop at the first
match.

### 2.a — Is the divergence on a floating-point value?

If the diverging field is a `f32`/`f64` (in the canonical encoding the
hash covers), the answer is almost always **determinism bug in
FrankenEngine**. The README's Numeric Discipline rule is unambiguous:
floating-point is forbidden in any position that affects a content
hash. Any `f64` in a hashed field is a violation of the discipline,
not a platform-specific quirk to tolerate.

**File a bead** with priority P1 and a label of `track-K`,
`determinism`. Name the exact field path. Cite the README rule. The
fix shape is "convert the field to fixed-point millionths".

### 2.b — Is the divergence on a map iteration order or set order?

If the diverging field is a serde-encoded `HashMap`, `HashSet`, or a
non-`BTreeMap`/`BTreeSet` collection that participates in canonical
bytes, this is a **determinism bug**: `HashMap`/`HashSet` hash seeds
vary across platforms and runs. The README's Determinism Discipline
rule mandates `BTreeMap`/`BTreeSet` here.

**File a bead** with priority P1. The fix shape is "swap the
collection type and re-emit the canonical encoding".

### 2.c — Is the divergence on a length-unprefixed concatenation of
variable-length fields?

If two distinct field decompositions could produce the same byte
stream under the gate's encoding (the README's "length-prefix
variable-length fields before concatenating into a hash input" rule),
the divergence on one platform may be exposing aliasing the other
platform happened to avoid by accident. This is a **determinism bug**
even if only one platform observes it today.

**File a bead** with priority P1 and a label of `length-prefix`. The
fix shape mirrors `attestation_handshake.rs` commit `3f28d071` — wrap
each variable-length field in an `append_len_prefixed_bytes` helper.

### 2.d — Is the divergence on a system-clock or wall-time-derived
value?

If the diverging field is any wall-clock value (`SystemTime`,
`UNIX_EPOCH`-relative timestamp, etc.), this is a **determinism bug** —
wall clocks are not in the deterministic-replay envelope. The runtime
exposes `DeterministicTimestamp` for hashed contexts; if a path is
using `SystemTime::now()` instead, the path is wrong.

**File a bead** with priority P1 and a label of `wall-clock-leak`.

### 2.e — Is the divergence on a PID, thread ID, hostname, or other
environmental value?

If the diverging field is a value that necessarily varies between
machines (host PID, MAC address, hostname, filesystem inode number,
worker uuid), this is a **worker-environment issue**: the artifact
should not be carrying that value, or the value should be normalised
before hashing.

**File a bead** with priority P2 and a label of `env-leak`. The fix
shape is to omit the field from the hash input, or replace it with a
content-derived deterministic id.

### 2.f — Is the divergence on a path string?

Filesystem paths are a frequent source of cross-platform drift
(`/` vs `\`, case-sensitivity, mount-point differences, temp-dir
prefixes). If the diverging field is a path, classify:

- **Absolute path with the worker's home directory or temp dir**: a
  worker-environment issue. The artifact should be using a path
  relative to a stable anchor (`PROJECT_ROOT`, `WORKLOAD_BUNDLE_ROOT`).
- **Path containing forward-vs-backslash differences**: a
  determinism bug. The serialisation must normalise path separators
  before hashing.
- **Path differing only in case**: usually a Windows-vs-Linux
  filesystem semantics drift. The artifact should fold case to lower
  before hashing, OR the workload should not rely on case-sensitive
  resolution at all.

### 2.g — Is the divergence on a CPU-feature-conditional code path?

If the platform that diverged has a different CPU feature set
(AVX-512 on x64 but not on arm64, NEON on arm64 but not on x64, SVE on
some arm64 but not others), and the divergence is on a value produced
by a path that branches on those features, this is a **determinism
bug** in the optimisation pass. Optimisations that branch on host CPU
features must produce identical outputs across feature sets — the
runtime's job is to converge the observable behaviour, not to expose
the feature.

**File a bead** with priority P1 and a label of `cpu-feature-leak`.
The fix shape is to remove the feature-conditional branch from the
optimisation output (the branch may stay in the dispatcher; the
artifact it produces must not).

### 2.h — Is the divergence on a Rust nightly-only behavior?

If the workers use different nightly versions (the README documents
`i128::div_ceil` as unstable on the project's nightly window), the
divergence may be caused by a function whose behaviour changed between
nightlies.

**Action**: pin both workers to the same nightly. This is a
worker-environment issue, not a FrankenEngine determinism bug. File a
bead with priority P2 + label `toolchain-drift` so the matrix worker
provisioning includes a pinned-nightly version.

### 2.i — None of the above

If the divergence does not fit any of 2.a–2.h, you have an unclassified
cross-platform regression. The triage packet (Step 4) is what unblocks
the Track K maintainers.

## Step 3 — Local reproduction

Before filing the bead, reproduce locally on at least one of the two
platforms:

```bash
./scripts/run_rgc_cross_platform_matrix.sh \
    --workload <workload_id> \
    --platform <linux-x64|macos-arm64|windows-x64> \
    ci
```

Capture the resulting `divergence_log.jsonl` (single-platform; you
need the second platform's log from the CI artifact to compare). Confirm
the divergence is present.

If you cannot reproduce locally on either platform that diverged in CI,
the bug is likely an environmental fluctuation (worker resource
pressure, transient I/O, scheduler quirk). Re-run CI before filing —
non-reproducible reports waste reviewer time and erode trust in the
gate.

## Step 4 — File the cross-platform regression bead

A high-quality cross-platform regression bead carries:

| Required | What to put |
|---|---|
| **Title** | `[Track K] <workload_id> diverges <field_path> across <platform-a> vs <platform-b>` |
| **Priority** | P1 for determinism bugs (2.a, 2.b, 2.c, 2.d, 2.f-determinism, 2.g). P2 for env / toolchain (2.e, 2.f-env, 2.h). |
| **Labels** | `track-K`, `cross-platform`, plus a class label from Step 2 (`determinism`, `length-prefix`, `wall-clock-leak`, `env-leak`, `cpu-feature-leak`, `toolchain-drift`). |
| **Body** | The triage packet: workload_id, both platform hashes, the failing field path, the classification from Step 2, the reproduction command, and the operator's own attempt to reproduce. |
| **Acceptance** | A regression test that runs the same workload on both platforms and asserts identical canonical bytes for the field that diverged. |

Attach the triage packet:

- `divergence_log.jsonl` (the CI artifact)
- `worker_facts.json` from both platforms
- The single-platform replay output you captured in Step 3

## Step 5 — Coordinate with Track K maintainers

If your classification is P1 and the divergence touches a hot code
path (parser, lowering, evidence emission, hash_tiers itself), notify
the Track K maintainers via Agent Mail. They may need to coordinate a
roll-forward fix because the matrix gate is part of every release
artifact's evidence bundle and a P1 divergence blocks publication.

## What NOT to do

These are the common wrong responses to a cross-platform divergence
report; resist all of them.

- **Do not** add a per-platform `cfg(target_os=...)` branch to silence
  the divergence. The branch will hide the bug; it will reappear the
  next time the matrix expands.
- **Do not** widen the hash input's tolerance ("ignore the last 16
  bytes", "compare only the first N fields"). The hash is the
  evidence; a hash with tolerance is not evidence.
- **Do not** add the workload to a per-platform skip list without
  filing the bead. A skip list without a tracking bead is a silent
  regression.
- **Do not** rebase the divergent commit out of history. The CI
  divergence record is the audit trail; preserving it lets future
  bisects find the introduction point.
- **Do not** assume "it passes on my Linux machine therefore it's not
  a Linux bug". The matrix worker may be running a different kernel
  version, glibc version, or filesystem.

## Cross-references

- README §"Determinism discipline" and §"Numeric Discipline Deep-Dive"
  — the rule source these classifications cite.
- `crates/franken-engine/src/hash_tiers.rs` — `ContentHash` type and
  helpers.
- `crates/franken-engine/src/deterministic_serde.rs` — canonical
  encoding (length-prefix rules, NaN canonicalisation, BTree-only
  collections in hashed positions).
- [`docs/operator-gates/RGC_GATES_REFERENCE.md`](./RGC_GATES_REFERENCE.md)
  — the broader RGC gate catalogue.
- Sibling operator runbooks
  ([`ADDING_A_NEW_CAPABILITY.md`](./ADDING_A_NEW_CAPABILITY.md),
  [`INTERPRETING_NODE_BUN_COMPARISON_RESULTS.md`](./INTERPRETING_NODE_BUN_COMPARISON_RESULTS.md),
  [`FORMAL_METHODS_WORKFLOW.md`](./FORMAL_METHODS_WORKFLOW.md)) —
  same diagnose / decide / act / verify pattern.
