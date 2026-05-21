# Reproducibility-Triple Emission Audit — bd-cixqu.14.1

Audit of which RGC gate scripts emit the reproducibility triple defined
in [`docs/REPRODUCIBILITY_CONTRACT.md`](./REPRODUCIBILITY_CONTRACT.md):

- `env.json` — execution environment + runtime context
- `manifest.json` — bundle identity + provenance + artifact paths
- `repro.lock` — provenance lock / verifier-input hashes

A claim passes the publication gate only when all three are present,
schemas validate, canonical hashes match, provenance links resolve, and
deterministic replay checks pass (`REPRODUCIBILITY_CONTRACT.md`
§"Scope and Gate").

## Method

Detection is structural, not runtime: the audit considers a gate
script "to emit" an artifact when a literal reference to the artifact
filename appears in the script body (line comments stripped first).
The audit pairs with a follow-on runtime probe under bd-cixqu.14.3
(`run_rgc_reproducibility_universality.sh`) which actually invokes
each gate and inspects the output bundle.

Run the audit:

```bash
scripts/audit_reproducibility_triple_emission.sh           # markdown table
scripts/audit_reproducibility_triple_emission.sh --summary # counts only
scripts/audit_reproducibility_triple_emission.sh --json    # JSONL stream
scripts/audit_reproducibility_triple_emission.sh --fail-on-gap
```

The script lives at `scripts/audit_reproducibility_triple_emission.sh`.
It exits non-zero with `--fail-on-gap` if any gate is missing at least
one artifact, suitable for wiring into the bd-cixqu.14.3 universality
gate.

## Current state (snapshot)

```
total_gates: 64
env_json_emitters:        5
manifest_json_emitters:  59
repro_lock_emitters:      5
full_triple_emitters:     5
no_emission:              5
```

Re-run `scripts/audit_reproducibility_triple_emission.sh --summary` to
refresh the counts after backfill PRs land.

### Full-triple emitters (5 / 64)

| Gate | env.json | manifest.json | repro.lock |
|---|---|---|---|
| `run_rgc_benchmark_freshness_gate.sh` | yes | yes | yes |
| `run_rgc_evidence_ledger_stitching.sh` | yes | yes | yes |
| `run_rgc_signature_drift_gate.sh` | yes | yes | yes |
| `run_rgc_statistical_validation_pipeline.sh` | yes | yes | yes |
| `run_rgc_tail_latency_control_plane.sh` | yes | yes | yes |

These five gates already conform to the contract and are the reference
shape every other gate should match.

### No-emission gates (5 / 64)

| Gate | Notes |
|---|---|
| `run_rgc_cross_platform_matrix.sh` | Distinct from the `_gate.sh` variant; needs full triple wiring. |
| `run_rgc_fleet_convergence_slo_gate.sh` | New gate; never wired through `proof_contract_write_standard_bundle`. |
| `run_rgc_tee_attestation_smoke.sh` | Smoke harness; arguably exempt, but a smoke that wants to claim observation must still emit. |
| `run_rgc_translation_validation_pilot.sh` | Pilot gate from bd-cixqu.7.6 — produces no bundle today. |
| `run_rgc_verification_coverage_matrix.sh` | Distinct from the `_gate.sh` variant; needs full triple wiring. |

These five are the highest-priority backfill targets — they currently
emit no reproducibility artifact at all, so any claim that names one of
them is unreproducible by construction.

### Manifest-only gates (54 / 64)

Every other gate emits `manifest.json` (via
`proof_contract_write_standard_bundle` in `scripts/lib/proof_artifact_contract.sh`)
but neither `env.json` nor `repro.lock`. Backfilling them is a
mechanical pattern: each gate already has a `run_dir` variable; the fix
is to add an `env.json` emit step before the manifest write and a
`repro.lock` emit step after, mirroring the five full-triple gates.

The 54-entry table is the audit script's default markdown output. Read
it via:

```bash
scripts/audit_reproducibility_triple_emission.sh
```

## Backfill protocol

For each gap, follow this protocol (matches the pattern in the five
full-triple gates):

1. **Source the helper**: confirm the gate script already sources
   `scripts/lib/proof_artifact_contract.sh`. If not, add the source line
   near the top.
2. **env.json**: write a JSON document under `${run_dir}/env.json`
   capturing `rustc --version`, target triple, Cargo lockfile hash,
   environment variables relevant to the run (whitelisted; see
   `scripts/lib/proof_artifact_contract.sh::proof_contract_write_redaction_policy`
   for the redaction rule).
3. **manifest.json**: already emitted by `proof_contract_write_standard_bundle`
   — no change required for the 54 manifest-only gates.
4. **repro.lock**: a sha256-keyed JSON document binding every input
   file the gate consumed (workload sources, fixtures, lockfiles, claim
   matrix snapshot) to its content hash at run time. The reference
   gate is `run_rgc_evidence_ledger_stitching.sh:200` which lists
   `env.json` alongside the other bundle artifacts.
5. **Re-run** `scripts/audit_reproducibility_triple_emission.sh
   --fail-on-gap` and confirm the backfilled gate now appears in the
   full-triple list.

Each backfill is a single-gate change — keep PRs small so reviews
focus on one script at a time.

## Wire-up to bd-cixqu.14.3

The follow-on universality gate (`bd-cixqu.14.3`) will run this audit
tool with `--fail-on-gap` as one of its preflight steps, so closing
this bead's backfill work is the gating dependency for landing the
gate's CI integration.

Until backfill is complete, the universality gate should run the audit
in **warn** mode (`--summary` only) and surface the gap count in its
report.

## Bead anchors

- This audit: **bd-cixqu.14.1**.
- Track parent: **bd-cixqu.14** (Track N — reproducibility-bundle
  universality + third-party verifier).
- Blocks: **bd-cixqu.14.2** (third-party verifier docker image) and
  **bd-cixqu.14.3** (`run_rgc_reproducibility_universality.sh ci`),
  both of which depend on the triple being universal across the gate
  set.
- Reproducibility-contract source of truth:
  [`docs/REPRODUCIBILITY_CONTRACT.md`](./REPRODUCIBILITY_CONTRACT.md).
- Standard-bundle helper:
  [`scripts/lib/proof_artifact_contract.sh`](../scripts/lib/proof_artifact_contract.sh).
- Sibling operator runbooks:
  [`docs/operator-gates/RGC_GATES_REFERENCE.md`](./operator-gates/RGC_GATES_REFERENCE.md),
  [`CROSS_PLATFORM_INCIDENT_TRIAGE.md`](./operator-gates/CROSS_PLATFORM_INCIDENT_TRIAGE.md)
  (bd-cixqu.11.6),
  [`INTERPRETING_NODE_BUN_COMPARISON_RESULTS.md`](./operator-gates/INTERPRETING_NODE_BUN_COMPARISON_RESULTS.md)
  (bd-cixqu.5.8).
