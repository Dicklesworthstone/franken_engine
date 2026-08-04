# ADR-0011: Collector and Allocator Selection Must Pass an Ecosystem Scan Before Any In-Tree Implementation

- Contract marker: `CAE-ADR-0011-V1`
<!-- CAE-APPROVAL-STATE-HEADER-BEGIN -->
- Status: Proposed — explicit project-owner approval is required
<!-- CAE-APPROVAL-STATE-HEADER-END -->
- Date proposed: 2026-07-24
- Owners: FrankenEngine runtime maintainers (heap/GC substrate)
- Decision authority: project owner
- Governing bead: `bd-performance-conformance-bridge-tu32j.4.21`
- Gates: `BRIDGE-03.8` (collector bakeoff), `BRIDGE-03.17` (young/unified space),
  `BRIDGE-03.18` (mature/unified space), and `bd-o4cbn.3` (PERF-H7 mimalloc)
- Plan references: `docs/plans/PLAN_TO_CREATE_FRANKEN_ENGINE.md` §7 (performance
  doctrine), §8.6 (determinism boundary contract)

<!-- CAE-APPROVAL-STATE-NOTICE-BEGIN -->
> [!IMPORTANT]
> This ADR is not accepted yet and deliberately leaves
> `implementation_authorized=false`. No collector space, allocator swap, or
> barrier implementation may land on the strength of this draft. Acceptance
> requires an explicit project-owner decision recorded against the evaluation
> results this ADR mandates.
<!-- CAE-APPROVAL-STATE-NOTICE-END -->

## Context

`BRIDGE-03` schedules a collector-architecture bakeoff (`BRIDGE-03.8`) followed
immediately by implementation of the selected young/unified and mature/unified
spaces (`BRIDGE-03.17`, `BRIDGE-03.18`), and `bd-o4cbn.3` (PERF-H7) proposes
mimalloc as the global allocator. None of those beads names a single existing
Rust-ecosystem artifact as a candidate.

The alien-graveyard **Ecosystem Scan Rule** is binding before S/A implementation
priority is assigned: record whether a relevant Rust crate already exists, and
either adopt it or document precisely why it fails our constraints
(performance, determinism, unsafe policy, licence, portability).

The risk this ADR exists to prevent is specific and large. Writing a production
garbage collector is a multi-year effort with a long tail of subtle defects in
weak references, ephemerons, finalization ordering, and write barriers. Building
one that ends up *worse* than an off-the-shelf collector, while the measured
bottleneck lies elsewhere entirely, is the single largest schedule risk in the
performance program. The current measured position — roughly 1,087x slower than
Node and 1,264x slower than Bun on the committed `docs/perf/e2_denominator_bundle_v1`
corpus — has not yet been attributed to the collector by any profile.

## Decision

**Collector and allocator selection is gated on a documented adopt-or-justify
evaluation. No space, barrier, or allocator implementation may begin until the
evaluation is complete and this ADR is accepted.**

### Mandatory candidate set

**Collectors**

| Candidate | Why it is in the set |
|---|---|
| **MMTk** | Rust, pluggable, production-exercised as the memory-management substrate for JikesRVM, OpenJDK, CRuby and V8 experiments. Ships Immix, MarkSweep, GenCopy and StickyImmix, so adopting it supplies several of the bakeoff arms at once. |
| **Immix** (Blackburn & McKinley 2008) | Mark-region collector; the reference design for good throughput with bounded fragmentation. |
| **LXR** (Zhao, Blackburn & McKinley, PLDI 2022) | Reference counting combined with Immix; current state of the art for low pause at high throughput. |
| **Incumbent in-tree** (`gc.rs`, `gc_pause.rs`) | The baseline that any replacement must actually beat. It must be measured, not assumed inferior. |

**Allocators**

| Candidate | Why it is in the set |
|---|---|
| **mimalloc** | Already proposed by `bd-o4cbn.3`. |
| **snmalloc** | Message-passing free design, specifically suited to the producer/consumer cross-thread free pattern that the `BRIDGE-11.3` share-nothing execution-cell shards will generate. |
| **System allocator** | Mandatory baseline comparator. |

### Mandatory scoring criteria

Each candidate must be scored — not asserted — on all seven:

1. **Determinism.** Can it run under the deterministic replay mode
   `BRIDGE-03.9` requires, with reproducible collection scheduling and
   safepoints? This is the criterion most likely to disqualify an external
   collector, and it outranks throughput.
2. **Unsafe posture.** How much `unsafe` does adoption import, and does it fall
   inside or outside the `ADR-0010` native-code capsule trust boundary? The
   repository is `#![forbid(unsafe_code)]`; importing a large unaudited unsafe
   surface outside the capsule is a trust-boundary change, not a dependency bump.
3. **Pause distribution.** p50/p95/p99/max pause measured on the real lifetime
   traces produced by `BRIDGE-03.7`, never on synthetic traces.
4. **Throughput and space overhead** versus the incumbent.
5. **Portability** across x86-64, AArch64 (Apple M4/M5) and Windows x64.
6. **Licence and supply chain**, with a `LEGAL.md` artifact where IP risk is
   plausible.
7. **Integration cost**, including whether the object model resulting from
   `BRIDGE-03.3` (hidden classes, slots, watchpoints) can present the tracing
   interface the candidate requires.

### Rules

- **Adopt-or-justify.** Every candidate above is either adopted or carries a
  written, evidence-backed rejection rationale. "We prefer to write our own" is
  not a rationale.
- **Determinism may not be traded for throughput.** If no external collector can
  satisfy the deterministic replay contract, that is a legitimate and sufficient
  justification to build in-tree — and this ADR records it as *the* justification,
  so the decision is auditable rather than assumed.
- **Measure before choosing.** The bakeoff runs all candidates on identical
  traces and identical hardware.
- **The incumbent is a candidate, not a floor to be replaced by default.**

## Consequences

**Positive.** The largest schedule risk in the performance program is converted
into a bounded, evidence-backed decision. If MMTk is adoptable, the project skips
a multi-year build and inherits several collector architectures at once. If it is
not adoptable, the reason is recorded permanently and the in-tree build proceeds
with a defensible mandate.

**Negative.** The evaluation costs real time before any collector code is
written, and it may conclude that the incumbent is adequate — which would make
the entire `BRIDGE-03.17`/`.18` implementation scope smaller than currently
planned. That is a desirable outcome, not a failure.

**Risk.** An external collector may satisfy every criterion except determinism.
That case must resolve toward determinism, because deterministic replay is a
constitutional property (Charter §3) and throughput is not.

## Proof artifacts required for acceptance

- Comparator benchmark bundle covering all candidates on identical traces and
  hardware, with `env.json`, `manifest.json` and `repro.lock`
- Seven-criterion scoring matrix with per-candidate evidence links
- `LEGAL.md` where IP risk is plausible
- Pause-distribution tables (p50/p95/p99/max) from `BRIDGE-03.7` real lifetime
  traces
- A recorded project-owner decision setting `implementation_authorized=true`
  and naming the selected collector and allocator

## Status of the evidence today

**None of the above has been produced.** This ADR defines the protocol only. It
deliberately fabricates no benchmark results and expresses no preference among
the candidates, because no comparative measurement has been taken. The first
work item is the bakeoff itself, and until it completes, `BRIDGE-03.17` and
`BRIDGE-03.18` remain blocked by `bd-performance-conformance-bridge-tu32j.4.21`.
