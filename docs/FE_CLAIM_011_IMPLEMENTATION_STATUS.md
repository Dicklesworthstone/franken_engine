# FE-CLAIM-011 Implementation Status

**Claim:** `>= 10x` reduction in successful red-team host compromise rate versus declared Node/Bun baselines  
**Owning bead:** `bd-1vwza`  
**Public state:** **TARGETED**  
**Implementation state:** **producer, verifier, and live workflow implemented; current promotion artifact not yet linked**  
**Machine corpus:** [`red_team_scenario_corpus_v2.json`](red_team_scenario_corpus_v2.json)

## Executive Status

The earlier FE-CLAIM-011 path was not suitable for claim promotion. It executed
FrankenEngine probes but hardcoded Node/Bun outcomes, and the first repeated-run
replacement then replayed five deterministic scenarios 100 times while reducing
each runtime/scenario pair to `any success`. A zero FrankenEngine cell could
therefore appear as an infinite reduction despite only five distinct scenarios.

The current implementation corrects both defects:

- Node, Bun, and FrankenEngine are all executed and receipt-bound.
- The denominator is ten exact, distinct security-critical scenarios.
- One hundred repetitions per runtime/scenario pair establish stability and
  replayability, not independent statistical samples.
- The aggregate is explicitly input-only and cannot self-promote.
- A zero FrankenEngine cell is conservatively treated as one hypothetical
  compromised scenario before threshold comparison.
- Only `franken_red_team_harness_gate` can emit the claim verdict.

The claim remains TARGETED because the repository does not yet link a current,
exact-revision, non-fixture live campaign and passing Rust verdict as its
promotion artifact.

## Shipped Components

| Layer | Status | Current contract |
|---|---|---|
| Exact scenario definition | Implemented | `docs/red_team_scenario_corpus_v2.json` fixes ten IDs, three attack classes, three runtimes, 100 stability repetitions, the zero-cell guard, and verdict scopes. |
| Python contract loader | Implemented | `scripts/red_team_scenario_corpus_contract.py` validates the JSON at import and rejects changed counts, runtime order, ownership, or semantic constants. |
| Single-repetition comparator | Implemented | `scripts/red_team_compromise_rate_metric.py` executes all three runtimes and emits hash-bound transcripts and witnesses. |
| Corpus adapter | Implemented | `scripts/red_team_compromise_rate_corpus.py` installs the exact v2 corpus and marks each local bundle receipt-only. |
| Campaign runner | Implemented | `scripts/run_bd_28otw_attacker_harness.sh` executes the complete matrix at the contract repetition floor and exposes scoped replay. |
| Generic receipt aggregation | Implemented, lower-level | `scripts/aggregate_red_team_trials.py` verifies source receipts and counts but is not a claim-verdict producer. |
| Scoped aggregate finalizer | Implemented | `scripts/red_team_scenario_corpus_harness.py` enforces proof-class scope, exact corpus identity, replay commands, hash rebinding, and stale-pass overwrite. |
| Semantic annotator | Implemented | `scripts/annotate_red_team_harness_semantics.py` rejects count-preserving scenario substitution and attack-class remapping. |
| Rust claim evaluator | Implemented | `franken_red_team_harness_gate` embeds the same JSON contract, validates typed and raw identities, applies the scenario denominator and zero-cell guard, and emits JSON/Markdown verdicts. |
| Focused CI | Implemented | `.github/workflows/red-team-repeated-trial-gate.yml` runs Python contract drills, receipt/replay tamper drills, rustfmt, and Rust CLI tests on every relevant change. |
| Live measurement workflow | Implemented | `.github/workflows/red-team-repeated-trial-measurement.yml` pins Node/Bun, builds exact binaries, preserves the corpus contract and logs, uploads evidence even on failure, and enforces the Rust verdict after preservation. |
| Current live promotion bundle | **Missing** | No current v2 campaign plus passing `claim_verdict.json` is linked from the authoritative claim matrix. |

## Metric Semantics

Let:

- `N` be the number of distinct contract-declared scenarios (`N = 10`);
- `B_node` be scenarios compromised under Node;
- `B_bun` be scenarios compromised under Bun; and
- `F` be scenarios compromised under FrankenEngine.

The conservative result is:

```text
baseline_reference = min(B_node, B_bun)
guarded_candidate = max(F, 1)
conservative_reduction_floor = baseline_reference / guarded_candidate
```

The threshold is met only when the floor is at least `10`. Repetition counts do
not enter that ratio. A runtime/scenario pair must instead have a stable outcome
across all required repetitions; mixed outcomes make the decision fail closed.

This is a result for the exact declared corpus and pinned runtime identities. It
is not a universal security theorem, population attack-rate estimate, or claim
about all Node/Bun configurations.

## Verification Layers

### 1. Machine-contract and proof-class smoke

```bash
python3 scripts/e2e/red_team_scenario_corpus_scope_smoke.py
```

Proves:

- the corpus adapter matches the JSON contract;
- repetition bundles are receipt-only;
- aggregate bundles are input-only;
- exact scenario/class identity is enforced;
- count-preserving substitutions fail;
- semantic failure overwrites stale aggregate success; and
- blocker artifacts contain no placeholder results.

### 2. Receipt, replay, and tamper smoke

```bash
bash scripts/e2e/red_team_repeated_trial_harness_smoke.sh
```

Proves the 10-scenario × 3-runtime × 100-repetition artifact shape, source
receipt hashing, aggregate replay, semantic annotation checking, and negative
tamper behavior. Its runtime results are synthetic fixtures and are not security
evidence.

### 3. Rust product gate

```bash
cargo test --no-default-features -p frankenengine-engine \
  --bin franken_red_team_harness_gate
cargo test --no-default-features -p frankenengine-engine \
  --test red_team_harness_gate_cli
```

Proves exact corpus acceptance and rejection of legacy five-scenario input,
lying counts, scenario substitution, class remapping, wrong typed scenario set,
claim-eligible aggregate input, wrong claim producer, unstable outcomes,
insufficient repetitions, and a reduction below the guarded threshold.

### 4. Live campaign

Dispatch `.github/workflows/red-team-repeated-trial-measurement.yml` at the exact
revision intended for certification. The workflow preserves:

- source revision;
- pinned Node/Bun versions;
- exact corpus JSON and SHA-256 digest;
- all repetition runtime inventories, transcripts, witnesses, and scenario rows;
- aggregate input and replay links;
- execution and Rust-evaluation logs; and
- `claim_verdict.json` plus `claim_verdict.md`.

The workflow uploads the bundle before failing on a negative verdict, preserving
counterevidence instead of deleting or hiding it.

## Promotion Checklist

All boxes must be satisfied before changing `FE-CLAIM-011` from TARGETED to
OBSERVED:

- [x] Node and Bun outcomes come from executed, pinned comparator binaries.
- [x] FrankenEngine outcomes come from the exact candidate binary.
- [x] Exact ten-scenario corpus is machine-defined and enforced in Python/Rust.
- [x] Repetitions are explicitly stability evidence, not independent samples.
- [x] Source revision, executable identities, scripts, manifests, transcripts,
      and witnesses are hash-bound.
- [x] Mixed outcomes, missing pairs, blockers, and ambiguity fail closed.
- [x] Zero-event candidate cell receives a one-scenario conservative guard.
- [x] Aggregate input is ineligible to self-declare the claim verdict.
- [x] Sole Rust verdict producer is enforced.
- [x] Focused positive and negative contract tests exist.
- [ ] A current non-fixture `10 × 3 × >=100` live campaign is complete.
- [ ] The live campaign's scoped replay succeeds from the preserved bundle.
- [ ] The Rust verdict exits `0` and records a conservative floor `>=10`.
- [ ] The full evidence bundle is retained at a stable repository or release
      artifact location.
- [ ] `docs/evidence/FE-CLAIM-011` is regenerated from that exact run rather
      than preserving its legacy receipt.
- [ ] Both authoritative claim-matrix JSON copies and the human companion are
      updated together.
- [ ] README wording is changed only after the claim gate accepts the linked
      artifact and verification command.

## Known Boundaries

- The corpus is intentionally finite and exact. Passing it says nothing about
  attacks outside those ten scenarios.
- Seven scenarios currently fall under `ambient_authority_escape`; attack-class
  diversity is three, but scenario diversity is not class-balanced.
- Node and Bun are measured as configured by the workflow, not every deployment
  hardening profile.
- A deterministic parser rejection may be a fail-closed runtime disposition, but
  the transcript must identify the actual execution stage; unavailable or
  ambiguous execution never counts as containment.
- The zero-cell guard is deliberately simple and conservative. Future expansion
  to probabilistic population claims requires a separately specified sampling
  model, uncertainty method, and bead; it must not reinterpret these stability
  repetitions after the fact.

## Next Dependency-Ordered Work

1. Obtain a green focused contract run at current `main`.
2. Dispatch the live measurement workflow at a quiescent exact revision.
3. Inspect every runtime/scenario pair for stable explicit dispositions and
   verify the aggregate replay.
4. Preserve the complete bundle, including a negative verdict if one occurs.
5. Only on a passing current verdict, regenerate FE-CLAIM-011 evidence and
   promote the matrix through the normal claim gate.
6. If the guarded floor is below `10`, expand or improve the engine/corpus based
   on observed counterexamples rather than changing the denominator post hoc.
