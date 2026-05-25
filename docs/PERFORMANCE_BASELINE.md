# FrankenEngine Performance Baseline

**Last Updated:** 2026-04-16  
**Baseline Version:** FrankenEngine baseline interpreter (not JIT-optimized)  
**Artifact Location:** `artifacts/performance_baselines/2026-04-16_12-41-04/`

## Executive Summary

FrankenEngine is a **security-first baseline interpreter** designed for deterministic execution, containment, and replay capabilities. Raw performance is intentionally traded for security guarantees, deterministic behavior, and governance features.

**Key Point:** FrankenEngine is currently 10-100x slower than V8/JavaScriptCore JIT engines for compute-intensive workloads. This is expected and acceptable given the security/determinism trade-offs.

## Measured Performance Baselines

All numbers below are measured on Linux x64 with Node.js v24.3.0, using 100% reproducible benchmark artifacts.

### Micro-Benchmark Results

| Operation | Measurement | Operations/Second | Notes |
|-----------|-------------|-------------------|-------|
| Integer arithmetic | 20ms for 1M additions + 100K mul/div | ~50M ops/sec | Basic math operations |
| Function calls | 47ms for 1M+ mixed calls | ~21M calls/sec | Various call patterns |
| Object creation | 167ms for 100K objects | ~600K objects/sec | Multiple creation patterns |
| Array operations | 122ms for mixed array ops | Varies by operation | Push/pop, map, filter, etc. |
| String operations | 183ms for mixed string ops | Varies by operation | Concat, search, replace |
| JSON operations | 1,941ms for 1K roundtrips | ~500 roundtrips/sec | Parse/stringify cycles |
| Property access | 24ms for 1M property reads | ~42M reads/sec | Object property access |
| Closures | Variable (by capture count) | ~10M calls/sec | Closure variable capture |
| Exception handling | Variable (by throw frequency) | Variable | Try/catch overhead |
| Class instantiation | Variable (by complexity) | ~600K instances/sec | ES6 class creation |

### Macro-Benchmark Results

| Benchmark | Status | Duration | Description |
|-----------|--------|----------|-------------|
| JSON transformation | ✅ Completed | ~16ms | 1K users, 500 products, 2K orders |
| Tree traversal | ❌ Failed (timeout) | >60s | Binary tree DFS/BFS operations |
| Recursive algorithms | ✅ Completed | Variable | Fibonacci, Hanoi, QuickSort |
| Text processing | ✅ Completed | Variable | Regex, tokenization, analysis |
| Event emitter simulation | ❌ Failed (timeout) | >60s | Event-driven programming |

## Performance Context

### What These Numbers Mean

1. **Baseline Interpreter Performance:** These are unoptimized interpreter numbers without JIT compilation
2. **Security Overhead:** Every operation includes safety checks and containment validation
3. **Deterministic Constraints:** All optimizations must preserve bit-stable replay semantics
4. **Memory Safety:** All operations run through Rust's memory safety guarantees

### Comparison Context

**FrankenEngine vs V8/JavaScriptCore:**
- **Arithmetic:** ~10-50x slower (expected for interpreter vs JIT)
- **Object operations:** ~10-100x slower (safety overhead)
- **JSON processing:** ~10-50x slower (deterministic parsing)

**Why This Performance Profile Exists:**
- **Security first:** Every operation goes through containment checks
- **Deterministic replay:** Optimizations cannot break replay semantics
- **Memory safety:** Rust safety guarantees add overhead vs. unsafe C++
- **Extension isolation:** Runtime boundaries and monitoring add latency

### When FrankenEngine Makes Sense

FrankenEngine is appropriate when you need:
- **Deterministic execution** for replay and forensics
- **Security containment** for untrusted extensions
- **Governance and audit trails** for compliance
- **Memory safety** for critical infrastructure

FrankenEngine is NOT appropriate when you need:
- **Maximum raw performance** for compute-heavy workloads
- **Low-latency applications** with tight timing requirements
- **Existing Node.js performance expectations** without security needs

## Cached defaults: invariants for static cryptographic material

FrankenEngine caches frequently-accessed cryptographic keys using `LazyLock` to avoid repeated curve operations while maintaining security guarantees:

```rust
// Module-scope cache in evidence_ledger.rs
static DEFAULT_EVIDENCE_SIGNING_KEY: std::sync::LazyLock<SigningKey> =
    std::sync::LazyLock::new(|| {
        SigningKey::from_bytes(DEFAULT_EVIDENCE_SIGNING_KEY_BYTES)
            .expect("default evidence signing key bytes are non-zero (const)")
    });

static DEFAULT_EVIDENCE_VERIFICATION_KEY: std::sync::LazyLock<VerificationKey> =
    std::sync::LazyLock::new(|| DEFAULT_EVIDENCE_SIGNING_KEY.verification_key());
```

**Invariant:** The cached signing key is guaranteed to be byte-identical to a freshly-constructed key from the same constant bytes. This invariant is preserved automatically by ed25519-dalek's deterministic key construction API, which produces identical `SigningKey` instances from identical 32-byte seeds. The cache avoids expensive elliptic curve computation while maintaining cryptographic correctness and deterministic behavior required for evidence replay.

For evidence supporting this optimization, see `tests/artifacts/perf/20260520T214829Z-prof-pass1/06_HYPOTHESIS_LEDGER.md#h1`.

**Note:** Any additional cached cryptographic material must follow this same pattern: deterministic construction from constant bytes with LazyLock initialization to ensure thread-safety and replay compatibility.

## Reusable canonical-encoding buffers

This section is the API design for `bd-o4cbn.5.2` (PERF-H4.2). It specifies a
buffer-reuse entry point for `deterministic_serde` so hot-loop callers can stop
allocating a fresh `Vec<u8>` per encode. **No code lands here** — implementation
is `bd-o4cbn.5.3` (PERF-H4.3). The signatures below are corrected against the
*actual* code in `crates/franken-engine/src/deterministic_serde.rs`; the original
bead draft proposed a fallible `encode_into_with_buffer(...) -> Result<(), DeterministicSerdeError>`
plus an `estimate_size` helper, none of which match what exists.

### Reality check: the encoder is already recursion-safe

The internal encoder is **purely additive** on a single buffer:

```rust
// crates/franken-engine/src/deterministic_serde.rs (current code)
pub fn encode_value(value: &CanonicalValue) -> Vec<u8> {     // allocates fresh Vec per call
    let mut buf = Vec::new();
    encode_into(&mut buf, value);
    buf
}
fn encode_into(buf: &mut Vec<u8>, value: &CanonicalValue);   // private; buf-first; infallible
fn encode_into_impl(buf: &mut Vec<u8>, value: &CanonicalValue);
```

`encode_into_impl` only ever calls `buf.push(..)` / `buf.extend_from_slice(..)`
and recurses into child values **with the same `buf`** (see the `Array`/`Map`
arms). It never random-access reads what it wrote. Therefore one buffer threaded
through the whole recursion is already correct: a parent appends its tag/length,
then each child appends after it. There is **no buffer-sharing-during-recursion
hazard** to design around — the codebase solved it by construction.

Consequences for this design:

- The encoder is **infallible** (it clamps lengths to `u32::MAX` rather than
  erroring), so the public buffer entry returns `()`, **not** `Result`. There is
  no `DeterministicSerdeError`; the crate's error type is `SerdeError` and it is
  only produced on the *decode* path.
- No `estimate_size` is needed. Reuse amortizes allocation across calls, which is
  the whole point; a per-call size estimate would re-introduce a walk of the tree.

### 1. Public function signatures (for H4.3)

```rust
// crates/franken-engine/src/deterministic_serde.rs

/// Encode `value` into `buf`, reusing its existing capacity. `buf` is
/// `.clear()`-ed at entry, so callers may pass a dirty buffer from a prior
/// encode. Infallible and fully reentrant: the encoder appends to the single
/// `buf` as it recurses (it never reads back what it wrote), so nested
/// `Object`/`Array` values share `buf` without conflict.
pub fn encode_value_into(buf: &mut Vec<u8>, value: &CanonicalValue) {
    buf.clear();
    encode_into(buf, value); // existing private additive encoder
}

/// Allocating convenience entry — unchanged behavior, now defined in terms of
/// the buffer-reuse path. Single-shot callers keep using this.
pub fn encode_value(value: &CanonicalValue) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_value_into(&mut buf, value);
    buf
}
```

Naming note: the public entry is `encode_value_into` (mirrors the existing public
`encode_value`), **not** `encode_into_with_buffer` from the draft. `encode_into`
is already taken by the private buf-first encoder; reusing the `encode_value*`
prefix keeps the public surface coherent and avoids a clash.

### 2. Caller-owned pool (per-loop, single-threaded)

```rust
/// A per-loop buffer the caller owns and reuses across many encodes. Holds one
/// growable `Vec<u8>`; capacity persists across `encode` calls. Single-threaded
/// by use, not by type: `encode(&mut self)` takes `&mut self`, so the borrow
/// checker already forbids concurrent calls on one pool. (If a hard `!Sync`
/// marker is ever wanted, add `PhantomData<core::cell::Cell<()>>`; it is not
/// required for soundness here.)
pub struct EncodeBufferPool {
    buf: Vec<u8>,
}
impl EncodeBufferPool {
    pub fn new() -> Self { Self { buf: Vec::new() } }
    pub fn with_capacity(cap: usize) -> Self { Self { buf: Vec::with_capacity(cap) } }
    /// Encode into the owned buffer and return a borrow of the bytes. No
    /// `Result`: encoding is infallible.
    pub fn encode(&mut self, value: &CanonicalValue) -> &[u8] {
        encode_value_into(&mut self.buf, value);
        &self.buf
    }
}
```

A hot loop that hashes many records holds one pool and reuses it:

```rust
let mut pool = EncodeBufferPool::with_capacity(4096);
for record in records {
    let bytes = pool.encode(&record.canonical_value());
    sink.push(ContentHash::compute(bytes));
}
```

### 3. Caller adoption (scope for H4.3)

`encode_value` has ~191 call sites. The overwhelming majority are in
`golden_vectors.rs` and other tests/one-shot paths — **leave those unchanged**
(`encode_value` stays). Convert only the hot, repeated-encode loops to hold an
`EncodeBufferPool` (or a plain reused `Vec<u8>` + `encode_value_into`):

- `flow_envelope.rs` — `encode_value(&unsigned_view())` on the sign/verify path
- `module_resolver.rs` — per-module digest (`ContentHash::compute(&encode_value(..))`)
- `react_compile_operator_surface.rs`, `module_compatibility_matrix.rs` — canonical-value encodes in repeated operations

### 4. Invariants

- `encode_value_into` `.clear()`s `buf` at entry → output never observes stale
  bytes from a previous encode.
- The encoder is purely additive on `buf` (only `push`/`extend_from_slice`, no
  random-access reads), so a single buffer threaded through recursion is correct;
  child encodes cannot corrupt the parent's view.
- `encode_value_into(&mut b, v)` produces byte-identical output to
  `encode_value(v)` for any `b` (the `.clear()` makes prior contents irrelevant).
  This is the H4.3 conformance property.
- `EncodeBufferPool::encode` is exclusive (`&mut self`); concurrent use on one
  pool is a compile error. Capacity persists across calls and is not cleared on
  `Drop`.

### 5. Why NOT a thread-local `RefCell<Vec<u8>>`

Rejected for two reasons. (a) Reentrancy: `encode` of a nested `Map`/`Array`
would re-enter and try to borrow the same `RefCell` again → `BorrowMutError`
panic. (b) Cost: thread-local access is non-trivial on the hot path, and it hides
the buffer's lifetime. An explicit caller-owned pool is faster and honest about
ownership. The single-additive-buffer design above sidesteps the reentrancy
problem entirely because there is exactly one buffer and recursion only appends.

### Acceptance (this bead)

- Design note recorded here and in the bead body. ✅
- Recursion-safety property stated explicitly (§4, and the "Reality check"). ✅
- No code change in this bead (implementation is `bd-o4cbn.5.3`). ✅

## Future Performance Roadmap

### Planned Optimizations (Future Releases)

1. **JIT Compilation Tier:** Planned for performance-critical paths while preserving replay
2. **Selective Fast Paths:** Verified optimizations for common operations
3. **Specialized Profiles:** Performance vs security trade-off configurations
4. **Native Compilation:** AOT compilation for known-safe code paths

### Performance SLOs

Current baseline (acceptable for security use cases):
- **Micro-operations:** 1-100M ops/sec depending on complexity
- **Macro-workloads:** 10-1000x slower than V8 (varies by workload)

Target improvement (with JIT tier):
- **Critical path operations:** 3-10x improvement while preserving safety
- **Non-deterministic workloads:** Near-V8 performance where safety allows
- **Deterministic workloads:** 2-5x improvement with verified optimizations

## Using These Baselines

### Performance Regression Detection

The performance regression gate ensures no unintentional slowdowns:
```bash
node scripts/performance_regression_gate.js --output ./artifacts/regression_check/
```

### Custom Benchmarking

Run your own workload against these baselines:
```bash
node scripts/run_baseline_benchmarks.js
```

### Artifact Verification

All performance claims are backed by reproducible artifacts in `artifacts/performance_baselines/`.

## Continuous Perf-Regression Gate (CI)

The `hot_paths` Criterion suite (`crates/franken-engine/benches/hot_paths.rs`)
is guarded in CI by `.github/workflows/perf_regression_gate.yml`
(PERF-INFRA.6).

**Trigger.** The workflow runs on pull requests that touch perf-sensitive
sources — `baseline_interpreter.rs`, `lowering_pipeline.rs`, `parser_arena.rs`,
`evidence_ledger.rs`, `deterministic_serde.rs`, `engine_object_id.rs`,
`hash_tiers.rs` — or anything under `crates/franken-engine/benches/`, any
`*.bench.rs`, or the gate script itself. It is also dispatchable manually.

**What it does.**

1. Builds and runs `cargo bench --bench hot_paths` (canonical flags:
   `CARGO_INCREMENTAL=0`, `RUSTFLAGS=-C linker=cc`).
2. Resolves the most recent frozen baseline under
   `tests/artifacts/perf/baselines/<git-sha>/` (newest `baseline_summary.json`
   timestamp).
3. Runs `scripts/perf/regression_gate.sh` comparing the current run against
   that baseline at a **5% threshold** per sub-bench. Any sub-bench whose
   mean exceeds the baseline by more than 5% fails the job.
4. On failure, uploads the regression bundle (`regressions.jsonl`,
   `regression_report.md`) plus the raw Criterion output as a CI artifact.

If no baseline has been frozen yet, the gate step is skipped with a notice
(nothing to compare against) and the job stays green.

### Freezing a baseline

Run the bench locally on a clean checkout, then freeze:

```bash
cargo bench --bench hot_paths
scripts/perf/freeze_baseline.sh "$(git rev-parse HEAD)"
git add tests/artifacts/perf/baselines/<git-sha>/
```

Retention policy: keep the last 12 baselines plus the current claim-matrix
anchor (see `tests/artifacts/perf/README.md`).

### Local regression check

The same gate the CI uses runs locally:

```bash
scripts/perf/regression_gate.sh \
    --baseline tests/artifacts/perf/baselines/<git-sha>/ \
    --current  target/criterion/real_runtime_hot_paths/ \
    --threshold-pct 5 \
    --out tests/artifacts/perf/regressions/<ts>/
```

Exit 0 = no regression, exit 1 = regression, exit 2 = usage/env error.

### Wall-clock A/B comparison

For cross-version wall-clock comparison of two built binaries:

```bash
scripts/perf/hyperfine_ab.sh <bin_a> <bin_b> <invocation_args...>
```

Emits `a_vs_b.json` and a `comparison.md` (mean / std-dev / 95% CI per binary
plus relative speedup) under `tests/artifacts/perf/hyperfine/<ts>/`.

## Profile-Guided Optimization (PGO)

PGO is driven through [`cargo-pgo`](https://github.com/Kobzol/cargo-pgo)
(PERF-ALIEN-3, parent bead `bd-o4cbn.11`). This section pins the toolchain
and the training corpus so instrumentation/optimization runs are
reproducible across machines.

### Toolchain setup (PERF-ALIEN-3.1)

```bash
cargo install cargo-pgo                       # pinned to >= 0.3.0
rustup component add llvm-tools-preview        # provides llvm-profdata / llvm-cov
cargo pgo --version                            # acceptance: prints cargo-pgo-pgo 0.3.0
```

`llvm-tools-preview` supplies the `llvm-profdata` binary `cargo-pgo` uses to
merge the raw `.profraw` files emitted by an instrumented build. The
nightly toolchain already in use for this crate (see the project default
toolchain) ships these components.

### Training corpus

The PGO profile is collected by exercising the runtime's real hot paths,
not synthetic micro-loops, so the merged profile reflects production-shaped
control flow. Two input sources make up the corpus:

1. **`real_runtime` hot-path bench inputs** — the
   `crates/franken-engine/benches/hot_paths.rs` Criterion suite running in
   its `real_runtime` mode (parser-arena, lowering, baseline-interpreter,
   iterator-protocol, scheduler, and evidence digests). These drive the
   parse → lower → execute → evidence pipeline end to end.
2. **Macro workloads** — every script under `benchmarks/macro/`:
   - `event_emitter_simulation.js`
   - `index.js`
   - `json_transformation.js`
   - `recursive_algorithms.js`
   - `text_processing.js`
   - `tree_traversal.js`

   These cover allocation-heavy, recursion-heavy, string-heavy, and
   tree-walking patterns, broadening branch coverage beyond the micro hot
   paths.

Rationale: the `hot_paths` inputs concentrate samples on the
latency-critical inner loops the regression gate already guards, while the
macro scripts widen coverage so the optimizer does not over-fit to the
micro benches. The instrumentation/collection pass that consumes this
corpus is tracked separately in `bd-o4cbn.11.2` (PERF-ALIEN-3.2).

Collection and optimization runs use the canonical perf build flags
(`CARGO_INCREMENTAL=0`, `RUSTFLAGS=-C linker=cc`) so PGO artifacts compare
cleanly against the frozen baselines above.

## Honest Performance Statement

**FrankenEngine is intentionally slower than mainstream JavaScript engines.** 

We prioritize:
1. **Security and containment** over raw speed
2. **Deterministic behavior** over adaptive optimization
3. **Audit and governance** over execution latency
4. **Memory safety** over unsafe performance tricks

For workloads where these priorities align with your needs, FrankenEngine provides unique value. For workloads where raw performance is the primary concern, V8/JavaScriptCore remain better choices until our JIT tier ships.

**No artifact, no claim.** All performance statements in this document are backed by reproducible benchmark artifacts committed to this repository.