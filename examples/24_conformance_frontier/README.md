# 24 — Conformance Frontier (ranked coverage gaps)

Runs the `franken_coverage_frontier` operator binary over the hermetic
`franken-engine` ↔ `franken-core` **differential-oracle seed corpus** (no Test262
checkout, no network, no real bead filing) and walks every read mode of the E7
conformance frontier.

```bash
./examples/24_conformance_frontier/demo.sh
```

The demo:

1. **Ranked worklist** (`--rank`) — clusters the failure frontier by spec construct
   and orders them by `impact = failing_count × usage × locality` (fixed-point
   millionths), printing each cluster's `explanation` so the ranking is auditable.
2. **Weighted coverage summary** (`--coverage-summary`) — the six category views
   (`parser`, `builtin`, `control-flow`, `async`, `module`,
   `intentional-divergence`), the single headline executed-% figure, and the
   `floor_view` that exposes the weakest category.
3. **Auto-bead-filing plan** (`--file-beads`, plan-only) — one proposal per top-N
   cluster carrying its failing cases, priority, the reviewable `br create` command,
   and a scaffold (a real `IntrinsicRow {…}` snippet for `built-ins/*` gaps, a
   parser/lowering note for `language/*`, an oracle-triage note for runtime
   divergences).
4. **Determinism + idempotent dedup** — the plan is byte-identical across runs, and
   a cluster already recorded in a (throwaway, seeded) dedup ledger is **skipped**,
   never re-proposed.
5. **Truth gate** (`--cross-reference`) — cross-references clusters against the
   parser/lowering gap inventories and exits `3` if any cluster is an *undocumented*
   gap (the demo reports this without failing).

> The seed corpus is small (a couple of intentional `franken-engine` ↔
> `franken-core` divergences), so it produces only a handful of clusters. Point the
> binary at a real corpus (`--report <conformance.json>` or `--run-suite <tc39/test262>`)
> to rank the full frontier.

### Prerequisite

Build the binary first (the demo auto-discovers `target/release/franken_coverage_frontier`,
`target/debug/franken_coverage_frontier`, or `$FRONTIER_BIN`):

```bash
cargo build --release -p frankenengine-engine --bin franken_coverage_frontier
```

### Reading the output

| Mode | Field that answers "…" |
|---|---|
| `--rank` | `clusters[].impact_millionths` / `.explanation` — what to fix first |
| `--coverage-summary` | `observable_surface_executed_millionths`, `views[]`, `floor_view` — how much we execute |
| `--file-beads` | `proposals[].scaffold` / `.br_create_command`; `skipped[]` — what to file (and what was already filed) |
| `--cross-reference` | `undocumented_count`, `truth_gate_pass` — any regression growing the frontier? |

**Claim state.** The headline coverage figure is published as `FE-CLAIM-026`, which
is **TARGETED** — it is execution coverage (the engine evaluated a positive case
without an engine error, or correctly rejected a negative case), *not* a spec
conformance pass-rate. The stricter harness-based ES2020 pass-rate is far lower
(see `docs/test262_real_corpus_pass_rate_v1.json`).

### See also

- Operator runbook (modes, bundle anatomy, exit-code triage, "pick the next
  highest-value language gap"): [`runbooks/dw_conformance_frontier.md`](../../runbooks/dw_conformance_frontier.md)
- Full DW.STD gate: `./scripts/run_dw_conformance_frontier.sh ci`
- README section: *Conformance Frontier (ranked coverage gaps)*
