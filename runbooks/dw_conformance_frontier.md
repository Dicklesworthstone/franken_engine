# Runbook: Conformance Frontier (`franken_coverage_frontier`)

> Operator runbook per DW.DOCS ([`bd-fqlfw.12`](../docs/dueling_wizards/DW_DOCUMENTATION_AND_OPERATOR_ENABLEMENT_STANDARD.md)).
> Capability bead: `bd-fqlfw.7` (E7 Conformance Frontier). Doc bead: `bd-fqlfw.7.7`.
> Claim state: the published coverage figure is `FE-CLAIM-026`, **TARGETED** (see the
> claim-state note at the end).

## What this does (one paragraph)

The conformance frontier turns raw conformance FAILURES (Test262 and the
`franken-engine` ↔ `franken-core` differential oracle) into a prioritized,
machine-readable worklist. It clusters failures by the spec construct they
exercise, ranks the clusters by a transparent impact score, truth-gates them
against the parser/lowering gap inventories, publishes a single weighted coverage
figure split into six category views, and can emit a deduplicated auto-bead-filing
plan with E4 intrinsic-table scaffolds. Reach for it when you want to answer "which
language gap, if I fix it, unblocks the most stuck tests?" and to keep that answer
reproducible and free of silently-growing regressions. The operator surface is the
`franken_coverage_frontier` binary (this capability ships a dedicated binary, not a
`frankenctl` subcommand).

## Preflight

- **Build:** `cargo build --release -p frankenengine-engine --bin franken_coverage_frontier`
  (the demo and gate auto-discover `target/release` / `target/debug`, or `$DW_FRONTIER_BIN`).
- **Dependencies:**
  - `--engine-core-oracle` — **none** (a hermetic in-process seed corpus).
  - `--run-suite <dir>` — a local `tc39/test262` checkout.
  - `--report <path>` — a `franken_test262_runner` `ConformanceReport` JSON.
  - `--file-beads --execute` — the `br` beads CLI on `PATH` (filing is plan-only
    without `--execute`).
- **Inputs required:** at least one failure source (`--report`, `--run-suite`,
  and/or `--engine-core-oracle`). With none, the binary exits `2` and prints usage.

## Normal use

Pick exactly one report mode (`--rank`, `--cross-reference`, `--coverage-summary`,
`--file-beads` are mutually exclusive; default = raw cluster list):

```bash
bin=./target/release/franken_coverage_frontier

# Raw clusters: failures grouped by construct (content-hashed cluster_id).
"$bin" --engine-core-oracle --out clusters.json

# Ranked worklist: impact = failing_count × usage × locality (fixed-point millionths).
"$bin" --engine-core-oracle --rank --out rank.json

# Weighted ES2020 coverage summary: six views + headline + floor view.
"$bin" --engine-core-oracle --coverage-summary --out summary.json

# Truth gate: fail closed (exit 3) if any cluster is an UNDOCUMENTED gap.
"$bin" --engine-core-oracle --cross-reference --out xref.json

# Auto-bead-filing PLAN (plan-only; review before filing).
"$bin" --engine-core-oracle --file-beads --top-n 10 --out plan.json

# Actually file the plan (gated: requires --ledger; runs `br create` per proposal).
"$bin" --engine-core-oracle --file-beads --top-n 10 \
  --ledger docs/coverage/frontier_filed_ledger.json --parent bd-fqlfw.7 --execute --out execution.json
```

Real failure corpora (instead of the seed oracle):

```bash
# From a saved Test262 conformance report (repeatable).
"$bin" --report run_a.json --report run_b.json --rank --out rank.json

# Run Test262 in-process over a checkout (cap with --sample-count, filter with --pattern).
"$bin" --run-suite /path/to/tc39/test262 --sample-count 5000 --pattern 'language/**' --rank --out rank.json
```

The whole stack runs as a DW.STD gate that emits a content-addressed bundle:

```bash
./scripts/run_dw_conformance_frontier.sh ci                              # -> artifacts/dw_conformance_frontier/<ts>/
./scripts/e2e/dw_conformance_frontier_replay.sh bundle                   # verify the latest bundle
./scripts/check_conformance_frontier_docs.sh                             # doc-drift guard (docs vs --help/gate/matrix)
```

## Reading the artifact bundle (`artifacts/dw_conformance_frontier/<timestamp>/`)

| File | Answers |
|---|---|
| `run_manifest.json` | Did the gate pass? source revision, host facts, content hashes, the verify command. |
| `events.jsonl` | Step-by-step log (inputs / decision / outputs / hashes / timing). |
| `commands.txt` | Exact commands run, in order. |
| `steps/<n>_*.log` | Full stdout+stderr of step `<n>`. |
| `frontier_corpus/rank.json` | The live ranked worklist emitted by the gate's binary run. |
| `frontier_corpus/summary.json` | The weighted coverage summary emitted by the gate. |
| `frontier_corpus/plan_a.json`, `plan_b.json` | Two independent file-beads plans; the gate asserts they are byte-identical (determinism). |

The report JSONs the binary writes with `--out` carry their own `report_digest` /
`plan_digest` (a content hash over the report's identity fields), so two runs over
the same inputs produce the same digest — that is the determinism contract.

### Which report field answers which question

| Question | Mode | Field |
|---|---|---|
| Which constructs are failing, grouped? | (default) | `clusters[].cluster_id` / `.construct` / `.failing_count` |
| What should I fix first? | `--rank` | `clusters[]` in order; `.impact_millionths`, `.explanation` |
| How much of ES2020 do we execute? | `--coverage-summary` | `observable_surface_executed_millionths`; `views[]`; `floor_view` |
| Are there undocumented gaps (regressions)? | `--cross-reference` | `undocumented_count`, `truth_gate_pass` |
| What beads should I file, and the scaffold? | `--file-beads` | `proposals[].title` / `.body` / `.scaffold` / `.br_create_command` |
| What was already filed (skipped)? | `--file-beads` | `skipped[].cluster_id` / `.reason` |

## Exit codes

| Code | Meaning | Operator action |
|---|---|---|
| 0 | report/plan emitted (and truth gate passed, under `--cross-reference`) | none |
| 2 | usage error / no failure source selected / a `--execute` filing failed | re-check flags; pass a source; inspect the per-proposal `results[].message` for a `br create` failure |
| 3 | truth-gate failure: at least one cluster is an undocumented gap (`--cross-reference` only) | add the missing entry to `parser_gap_inventory.rs` / `lowering_gap_inventory.rs`, or fix the regression, then re-run |

The DW.STD gate (`run_dw_conformance_frontier.sh`) returns the standard
DW.STD codes: `0` pass, `1` fail-closed (a step failed before the manifest was
written — open the failing `steps/*.log`), `3` degraded (a required dependency was
unavailable; see the `degraded` event in `events.jsonl`).

## Failure triage

| Symptom | Cause | Fix |
|---|---|---|
| `error: no failure source selected` (exit 2) | no `--report` / `--run-suite` / `--engine-core-oracle` | pass at least one source |
| `--rank, --file-beads, --cross-reference, and --coverage-summary are mutually exclusive` | two report modes | pick one mode per run |
| `--execute requires --ledger <path>` | `--execute` without a ledger | add `--ledger <path>` so the dedup ledger persists |
| `--usage-signal requires --rank or --file-beads` | usage signal passed to the wrong mode | use it with `--rank` or `--file-beads`, or drop it |
| truth gate exits 3 with surprising clusters | a real undocumented gap (a new failure family with no inventory entry) | record it in the gap inventory or fix the regression; the gate is doing its job |
| gate live-corpus step fails with `unrecognized argument` | a **stale** `target/release` binary predating a newer mode | the gate builds a fresh dev binary by default; if you pinned `$DW_FRONTIER_BIN`, rebuild it |
| `--file-beads --execute` reports `ok:false` for some proposals (exit 2) | `br create` failed (e.g. `br` not on `PATH`, bad `--parent`) | read `results[].message`; the ledger still records the proposals that DID file, so re-running skips them |

## Runbook: pick the next highest-value language gap

This is the day-to-day loop an operator or AI agent runs to advance coverage.

1. **Rank the frontier.** From real corpora when available, else the seed oracle:
   ```bash
   ./target/release/franken_coverage_frontier --report latest_test262.json --rank --out rank.json
   ```
   (Add `--usage-signal usage.json` if you have a real npm-corpus construct-weight
   scan; without it `usage` is a neutral constant and ranking falls back to
   `failing_count × locality` — honest, never fabricated.)
2. **Read the top of the list.** `jq '.clusters[0]' rank.json` — the first cluster
   is the highest-impact gap. Its `.explanation` shows exactly how `failing_count`,
   `usage`, and `locality` combined, so the choice is auditable, not a black box.
3. **Confirm it is a documented gap, not a regression.**
   ```bash
   ./target/release/franken_coverage_frontier --report latest_test262.json --cross-reference --out xref.json
   ```
   Exit `3` means a top cluster is *undocumented* — record it in the gap inventory
   first (a regression masquerading as a frontier item).
4. **Get the scaffold.** `jq '.proposals[0]' <(./target/release/franken_coverage_frontier --report latest_test262.json --file-beads --out /dev/stdout)`
   gives the proposal for the top cluster: its failing sample cases, priority, the
   exact `br create` command, and a `scaffold`. For a `built-ins/*` cluster the
   scaffold is a real `IntrinsicRow {…}` snippet — fill in each `// TODO` field and
   add the matching impl fn (see *Extending FrankenEngine* and the E4 intrinsic
   table contributor guide). For `language/*` it is a parser/lowering note; for a
   runtime divergence it is an oracle-triage note.
5. **File it (optional, gated).** Review the plan, then:
   ```bash
   ./target/release/franken_coverage_frontier --report latest_test262.json --file-beads \
     --ledger docs/coverage/frontier_filed_ledger.json --parent bd-fqlfw.7 --execute
   ```
   The ledger is dedup-keyed on the content-hashed `cluster_id`: a cluster already
   filed (open OR closed bead) is skipped, so re-running the loop never files a
   duplicate. Each filed bead body embeds an autofile marker + its `cluster_id`, so
   the ledger can be rebuilt by grepping the tracker if it is ever lost.
6. **Fix, then re-measure.** After landing the fix, re-run `--coverage-summary` and
   confirm the relevant view (and ideally the `floor_view`) moved up.

## Claim-state note

The headline coverage figure is `FE-CLAIM-026`, whose matrix state is **`target`**
(`docs/claim_to_proof_matrix_v1.json`; owning bead `bd-fqlfw.7.4`; gate
`./scripts/run_coverage_summary_bundle_gate.sh ci`). What that means for a reader:

- The figure is **execution coverage, not a conformance pass-rate.** "Executed"
  means the engine evaluated a positive case without an engine error, or correctly
  rejected a negative case — assertion outcomes are *not* verified.
- On the ES2020-normative tc39/test262 profile (`language/*` + `built-ins/*`) the
  engine currently executes **~13.05%** (6201/47514) of the observable surface;
  the weakest view (`builtin`) is **~1.67%**.
- The stricter harness-based ES2020 conformance pass-rate is far lower (**~0.25%**,
  [`docs/test262_real_corpus_pass_rate_v1.json`](../docs/test262_real_corpus_pass_rate_v1.json)).
  Do not read the executed-% as a conformance score.
- The six weighted views (`parser`, `builtin`, `control-flow`, `async`, `module`,
  `intentional-divergence`) plus the floor view exist so a single percentage cannot
  be gamed: the floor exposes the weakest category. The figure is a conservative
  lower bound and **stays TARGETED** until coverage is materially higher.

See also the README *Conformance Frontier* section, the runnable demo
[`examples/24_conformance_frontier/demo.sh`](../examples/24_conformance_frontier/demo.sh),
and the coverage-summary bundle gate `./scripts/run_coverage_summary_bundle_gate.sh ci`.
