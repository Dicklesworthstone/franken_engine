# Runbook: Evidence Flight Recorder + Time-Travel Debugger (`frankenctl run --explain` / `frankenctl explain` / `frankenctl replay debug`)

> Operator runbook per DW.DOCS (`bd-fqlfw.12`). Capability beads: `bd-fqlfw.3`
> (epic), `bd-fqlfw.3.1`–`.3.4` (flight-recorder index + views + CLI),
> `bd-fqlfw.3.5` (time-travel debugger, children `.3.5.1`–`.3.5.5`),
> `bd-fqlfw.3.6` (capstone gate), `bd-fqlfw.3.7` (this runbook).

## What this does (one paragraph)

The flight recorder makes one `frankenctl run` self-explaining: `--explain`
emits a content-addressed **index** (`explain.json`) linking every artifact the
run produced — source, run report, evidence records — without inventing an
(N+1)th schema; `frankenctl explain` renders pure projections of that index
(narrative, evidence graph, replay recipe, counterfactual pointers). The
time-travel debugger (`frankenctl replay debug`) then navigates a captured
nondeterminism trace tick-by-tick — forward, backward, or `goto` — with event
breakpoints, a `why <tick>` causal explainer, and (with `--input`) live
inspection of registers, heap values, and IFC labels reconstructed by
re-executing the REAL interpreter. Backward stepping is re-run-from-checkpoint
(replay is byte-identical and deterministic), so nothing records per-tick state
and the debugger is the authoritative semantic model by construction.

## Normal use

```bash
# 1) Run with the flight recorder on: report + linked explain index.
frankenctl run --input ./ext.js --extension-id my-ext \
  --out ./artifacts/run.json --explain --explain-out ./artifacts/explain.json

# 2) Human summary of the index (what happened, which artifacts, which links):
frankenctl explain ./artifacts/explain.json

# 3) Full derived view bundle (all views are pure projections of the index):
frankenctl explain ./artifacts/explain.json --emit-bundle ./artifacts/explain-bundle

# 4) Time-travel debugging over a captured nondeterminism trace, with live
#    interpreter-state inspection reconstructed from the program source:
frankenctl replay debug --trace ./artifacts/trace.json --input ./ext.js \
  --script ./commands.jsonl --out ./artifacts/transcript.jsonl

# Capstone gate -> content-addressed bundle under artifacts/dw_flight_recorder/<ts>/
./scripts/run_dw_flight_recorder.sh ci              # routes Cargo through rch
DW_RUN_LOCAL=1 ./scripts/run_dw_flight_recorder.sh ci  # local fallback when rch is down

# Verify / replay an emitted gate bundle:
./scripts/e2e/dw_flight_recorder_replay.sh bundle artifacts/dw_flight_recorder/<ts>
```

## Which file answers which question (`--emit-bundle` directory)

| File | Answers |
|---|---|
| `explain.json` | The index itself: every artifact the run produced (content hash + stable key + schema id) and every typed link between them. Nothing is duplicated here — fields live in their owning schema, the index only points. |
| `explain.md` | "What happened, in order?" — the operator narrative rendered from the index. Start here in an incident. |
| `evidence_graph.json` | "What depends on what?" — nodes are artifacts, edges are the typed links (`DerivedFrom`, …). Use it to walk from a containment decision back to the exact source + policy inputs. |
| `replay.json` | "How do I reproduce this run?" — the replay recipe: which trace, which mode, which inputs, in verification order. |
| `counterfactuals.json` | "What would policy X have done instead?" — pointers into the counterfactual-replay surface for the run's decisions. |
| `commands.txt` | The exact commands behind the above, in order. |
| `repro.lock` | The pinned re-run recipe + determinism contract for the bundle. |

Byte-identity contract: identical `--input` source with identical flags yields a
byte-identical `run.json` **and** `explain.json` (asserted on every gate run by
`run_dw_flight_recorder.sh`'s two-pass diff). Note the run report embeds its own
`--out`/`--explain-out` paths, so "identical flags" includes identical output
paths — compare via copy, not via differently-named outputs.

## Time-travel debugger commands (`frankenctl replay debug`)

One JSON object per line (from `--script` or stdin), exactly one JSON response
line each; identical trace + script (+ `--input`) gives a byte-identical
transcript. Commands:

| Command | Effect |
|---|---|
| `{"cmd":"state"}` | Cursor position: current tick, total ticks, mode, checkpoint stats. |
| `{"cmd":"step"}` / `{"cmd":"back"}` | One tick forward / backward (backward = restore nearest sparse checkpoint + re-run, O(checkpoint interval)). |
| `{"cmd":"goto","tick":N}` | Jump to tick N (same re-run mechanics). |
| `{"cmd":"add_breakpoint","breakpoint":{...}}` | Arm one of: `{"type":"kind_is","kind":...}`, `{"type":"label_level_at_least","min_level":3}` (Secret=3), `{"type":"capability_denied"}`, `{"type":"malicious_posterior_above","threshold_millionths":200000}`. |
| `{"cmd":"run_until_break"}` | Advance to the next armed-breakpoint hit (or report none). |
| `{"cmd":"inspect"}` / `{"cmd":"inspect","tick":N}` | Registers, heap objects, and IFC labels at the tick. Served from `--state-snapshots` when supplied; otherwise, with `--input`, reconstructed by re-executing the real interpreter (see below). Fails closed when neither can serve the tick. |
| `{"cmd":"why","tick":N}` | The causal chain of security-relevant precursors at/before N, with the evidence-ledger `decision_id` for deep forensics. |
| `{"cmd":"events_at","tick":N}` | Raw normalized events at exactly tick N. |

### Live state reconstruction (`--input`, bd-fqlfw.3.5.5)

With `--input <source.js>` (optional `--input-goal script|module`), an `inspect`
for a tick with no pre-supplied snapshot re-executes the program with a state
capture armed at that tick and serves the observation (cached thereafter).
Honesty guarantees:

- The re-execution's nondeterminism trace must match the loaded `--trace`
  event-for-event, or the inspect fails closed — a module that does not
  correspond to the trace cannot serve state. (CLI gap: `frankenctl run` does
  not yet emit its recorded trace, so an end-to-end CLI inspect round-trip
  needs `--emit-trace` — tracked as `bd-9mr8o`; in-process reconstruction
  fidelity is pinned by `tests/flight_recorder_capstone.rs`.)
- Only an instruction boundary landing exactly on the tick produces state;
  otherwise the response is a fail-closed protocol error, never invented state.
- Heap-object labels are the join of the labels of every register from which
  the object is reachable — a projection of the runtime's register-granularity
  IFC state, not a second model.

### The agent loop for localizing a divergence

1. `{"cmd":"state"}` → note `total_ticks`.
2. Binary-search with `{"cmd":"goto","tick":M}` + `{"cmd":"inspect","tick":M}`,
   comparing the snapshot against the expected state (or a second trace's
   snapshot at the same tick) — snapshots are canonical JSON, so `diff` works.
3. At the first divergent tick, `{"cmd":"events_at","tick":M}` and
   `{"cmd":"why","tick":M}` name the security-relevant precursors; escalate the
   reported `decision_id` to the forensic-causation operator for the deep
   subgraph.

## Incident triage from a bundle

1. `frankenctl explain <explain.json>` — read the summary; then `--emit-bundle`
   and read `explain.md` for the ordered narrative.
2. `evidence_graph.json`: walk backward from the containment/decision artifact
   to its inputs; every link endpoint resolves to a content-addressed artifact
   (missing/stale endpoints are *flagged*, never invented).
3. `replay.json` + `repro.lock`: re-run `frankenctl replay run --mode strict`;
   strict mode aborts at the first divergence.
4. For "why did the runtime do X at tick N": `frankenctl replay debug` with the
   trace + `why <N>`, then `inspect` around N with `--input` for value/label
   ground truth.

## Failure triage

- **`inspect` fails with "re-execution trace diverged"** → the `--input` source
  (or its parse goal / interpreter config) is not the program that recorded the
  trace. Use the exact source pinned by the run's `repro.lock`.
- **`inspect` fails with "no instruction boundary landed exactly"** → a single
  instruction emitted several nondeterminism events across that tick; inspect a
  neighboring tick. The debugger will not fabricate intra-instruction state.
- **Two-pass byte-identity diff fails in the gate** → real nondeterminism in
  the run path (a regression against FE-CLAIM-013's fixed-input contract) — or
  differing output paths leaking into the self-referential report. Check the
  gate's `steps/` logs for the diff.
- **Gate hangs / fails on `rch exec`** → re-run with `DW_RUN_LOCAL=1`.
- **Replay wrapper reports "no complete bundle"** → the last gate run aborted
  before `run_manifest.json`; re-run `./scripts/run_dw_flight_recorder.sh ci`.

## Claim-state note

Deterministic replay for the declared high-severity inventory is **OBSERVED**
(`FE-CLAIM-003`), and fixed-input `compile`/`run` byte-identity is **OBSERVED**
(`FE-CLAIM-013`); the flight-recorder bundle and debugger ride on those
contracts. The debugger's reconstruction fidelity (reconstructed state equals
the originally-observed state at sampled ticks) is pinned by
`tests/flight_recorder_capstone.rs` and re-checked on every
`run_dw_flight_recorder.sh ci` bundle.
