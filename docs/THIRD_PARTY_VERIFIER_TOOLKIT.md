# Third-Party Verifier Toolkit (`franken-verify`)

This runbook describes how independent operators can verify FrankenEngine claim artifacts without running the FrankenEngine control plane.

## Scope

Current verifier surfaces:
- `benchmark`: verify benchmark claim consistency and cross-runtime workload fairness
- `replay`: verify incident replay bundle integrity/fidelity and optional signature/receipt/counterfactual checks
- `containment`: verify containment gate result invariants and latency-SLA compliance
- `attestation`: create signed publication-ready verifier attestations and verify attestation integrity/signatures
- `receipt`: existing unified receipt verifier pipeline

## Build

```bash
rch exec -- cargo build -p frankenengine-engine --bin franken-verify
```

Binary path:

```bash
./target/debug/franken-verify
```

## Verifier Suite Gate (`bd-3gsv`)

For deterministic verifier-lane validation, use the dedicated suite runner:

```bash
./scripts/run_third_party_verifier_suite.sh ci
```

Supported modes: `check`, `test`, `clippy`, and `ci` (default).

Execution contract:

- heavy Rust commands run through `rch`
- if `rch` reports local fallback, the suite fails closed
- deterministic environment metadata is sourced from `scripts/e2e/parser_deterministic_env.sh`
- each run emits artifacts under `artifacts/third_party_verifier/<timestamp>/`

Expected run artifacts:

- `run_manifest.json`
- `events.jsonl`
- `commands.txt`

Replay wrapper:

```bash
./scripts/e2e/third_party_verifier_replay.sh ci
```

## Repro.lock Scripted Environment (`bd-cixqu.14.2`)

External operators can verify a shipped reproducibility lock without knowing the
original gate script:

```bash
scripts/third_party_repro_lock_verifier.sh --lock artifacts/<bundle>/repro.lock --report verify_report.json
```

The verifier accepts both canonical `franken-engine.repro-lock.v1` locks and
the runbook backfill shape `frankenengine.reproducibility.lock.v1`. It extracts
the locked replay command sequence, enforces a fail-closed deterministic policy,
wraps direct Cargo commands with:

```bash
rch exec -- env CARGO_INCREMENTAL=0 RUSTFLAGS="-C linker=cc" bash -lc '<locked command>'
```

and emits `franken-engine.third-party-repro-lock-verifier-report.v1` with the
commands, source commit, deterministic-policy verdict, execution count, and
failed command if any.

Dry-run planning for release packages:

```bash
scripts/third_party_repro_lock_verifier.sh --lock artifacts/<bundle>/repro.lock --plan-only
```

Smoke coverage:

```bash
scripts/e2e/third_party_repro_lock_verifier_smoke.sh
```

## Usage

```bash
franken-verify receipt <receipt_id> --input <path> [--summary]
franken-verify benchmark --input <path> [--summary]
franken-verify benchmark audit --input <path> [--summary]
franken-verify benchmark fairness --input <path> [--summary]
franken-verify benchmark reproduce --bundle <dir> [--summary] [--output <path>]
franken-verify benchmark verify --bundle <dir> [--summary] [--output <path>]
franken-verify replay --input <path> [--summary]
    [--signature-key-hex <hex> | --signature-key-file <path>]
    [--receipt-key <signer_hex>=<verification_key_hex>]...
    [--receipt-key-file <path>]...
    [--counterfactual-config-file <path>]...
franken-verify containment --input <path> [--summary]
franken-verify attestation create --input <path> [--summary]
    [--signing-key-hex <hex> | --signing-key-file <path>]
franken-verify attestation verify --input <path> [--summary]
```

`--summary` emits a compact line suitable for CI gates.
Without `--summary`, the tool emits JSON reports.

JSON reports include:
- `confidence_statement`: deterministic confidence summary for the final verdict.
- `scope_limitations`: normalized list of skipped-scope reasons (for partial verification).

## Exit Codes

- `0`: verified/pass
- `20`: receipt signature layer failure (legacy receipt subcommand)
- `21`: receipt transparency layer failure (legacy receipt subcommand)
- `22`: receipt attestation layer failure (legacy receipt subcommand)
- `23`: stale data warning/failure (legacy receipt subcommand)
- `24`: partially verified (checks skipped)
- `25`: failed verification
- `26`: inconclusive verification
- `2`: CLI or input parse error

## Input Schemas

### Benchmark (`benchmark --input`)

```json
{
  "trace_id": "trace-bench-001",
  "decision_id": "decision-bench-001",
  "policy_id": "policy-bench-001",
  "input": {
    "node_cases": [
      {
        "workload_id": "boot-storm/s",
        "throughput_franken_tps": 3000.0,
        "throughput_baseline_tps": 900.0,
        "weight": null,
        "behavior_equivalent": true,
        "latency_envelope_ok": true,
        "error_envelope_ok": true
      }
    ],
    "bun_cases": [
      {
        "workload_id": "boot-storm/s",
        "throughput_franken_tps": 3000.0,
        "throughput_baseline_tps": 950.0,
        "weight": null,
        "behavior_equivalent": true,
        "latency_envelope_ok": true,
        "error_envelope_ok": true
      }
    ],
    "native_coverage_progression": [
      {
        "recorded_at_utc": "2026-02-23T00:00:00Z",
        "native_slots": 42,
        "total_slots": 48
      }
    ],
    "replacement_lineage_ids": ["lineage-a"]
  },
  "claimed": {
    "score_vs_node": 3.2,
    "score_vs_bun": 3.1,
    "publish_allowed": true,
    "blockers": []
  }
}
```

### Replay (`replay --input`)

```json
{
  "trace_id": "trace-verify-001",
  "decision_id": "decision-verify-001",
  "policy_id": "policy-verify-001",
  "verification_timestamp_ns": 6000,
  "current_epoch": 3,
  "bundle": { "...": "IncidentReplayBundle JSON" },
  "signature_verification_key_hex": "<64 hex chars>",
  "receipt_verification_keys_hex": {
    "<signer_engine_object_id_hex>": "<64 hex chars>"
  },
  "counterfactual_configs": []
}
```

Notes:
- `signature_verification_key_hex` is optional.
- `receipt_verification_keys_hex` is optional.
- `counterfactual_configs` may be empty for fidelity-only verification.
- CLI flags can layer auditor-side overrides without editing the input bundle:
  - `--signature-key-hex` / `--signature-key-file`
  - `--receipt-key` / `--receipt-key-file`
  - `--counterfactual-config-file`

### Replay auxiliary file formats

`--receipt-key-file` supports either:

1. JSON map (`signer_engine_object_id_hex -> verification_key_hex`)

```json
{
  "0101...": "a1b2..."
}
```

2. Line-oriented text (`<signer_hex>=<verification_key_hex>`, `#` comments allowed)

```text
# signer_id=verification_key
0101...=a1b2...
```

`--counterfactual-config-file` accepts either one JSON `CounterfactualConfig`
object or an array of configs.

### Containment (`containment --input`)

```json
{
  "trace_id": "trace-cont-001",
  "decision_id": "decision-cont-001",
  "policy_id": "policy-cont-001",
  "detection_latency_sla_ns": 500000000,
  "result": {
    "seed": 7,
    "scenarios": [
      {
        "scenario_id": "scenario-1",
        "fault_type": "NetworkPartition",
        "passed": true,
        "criteria": [
          {
            "name": "autonomous-isolation",
            "passed": true,
            "detail": "isolated in budget"
          }
        ],
        "receipts_emitted": 1,
        "final_state": "Quarantined",
        "detection_latency_ns": 100000000,
        "isolation_verified": true,
        "recovery_verified": true
      }
    ],
    "passed": true,
    "total_scenarios": 1,
    "passed_scenarios": 1,
    "events": [],
    "result_digest": "digest-001"
  }
}
```

### Attestation Create (`attestation create --input`)

This input wraps a previously produced verifier report plus publication metadata.
If `signing_key_hex` is provided, output includes a deterministic signature and signer verification key.
CLI overrides are also supported with:
- `--signing-key-hex`
- `--signing-key-file`

```json
{
  "report": {
    "claim_type": "benchmark",
    "trace_id": "trace-bench-001",
    "decision_id": "decision-bench-001",
    "policy_id": "policy-bench-001",
    "component": "third_party_verifier",
    "verdict": "verified",
    "checks": [],
    "events": []
  },
  "issued_at_utc": "2026-02-24T00:00:00Z",
  "verifier_name": "Verifier",
  "verifier_version": "v1.2.0",
  "verifier_environment": "linux-x86_64",
  "methodology": "benchmark_recompute_v1",
  "scope_limitations": ["requires equivalent workload environment"],
  "signing_key_hex": "<64 hex chars>"
}
```

### Attestation Verify (`attestation verify --input`)

Verifier checks:
- required attestation envelope fields
- context/verdict consistency against embedded report
- report digest integrity
- canonical statement template integrity
- signature validity (if signature fields are present)

Unsigned attestations verify as `partially_verified` (exit code `24`) with explicit `skipped: unsigned attestation`.

## Example Commands

```bash
franken-verify benchmark --input artifacts/claims/benchmark_claim.json --summary
franken-verify replay --input artifacts/claims/replay_claim.json --summary
franken-verify containment --input artifacts/claims/containment_claim.json --summary
franken-verify attestation create --input artifacts/claims/attestation_input.json > artifacts/claims/attestation.json
franken-verify attestation create --input artifacts/claims/attestation_input.json --signing-key-file artifacts/claims/attestation_signing_key.hex > artifacts/claims/attestation_signed.json
franken-verify attestation verify --input artifacts/claims/attestation.json --summary

# replay with auditor-side key/config overlays
franken-verify replay \
  --input artifacts/claims/replay_claim.json \
  --signature-key-file artifacts/claims/signature_key.hex \
  --receipt-key-file artifacts/claims/receipt_keys.json \
  --counterfactual-config-file artifacts/claims/counterfactual_branch.json \
  --summary
```

For machine ingestion:

```bash
franken-verify replay --input artifacts/claims/replay_claim.json > artifacts/claims/replay_verify_report.json
```

Example report fields of interest:

```json
{
  "verdict": "partially_verified",
  "confidence_statement": "all 7 checks passed with 1 scope limitation(s): unsigned attestation",
  "scope_limitations": ["unsigned attestation"]
}
```

## Verification Semantics

- Benchmark:
  - `benchmark audit`: recomputes publication-gate scores and blocker/publish decisions from claim input
  - `benchmark fairness`: verifies node/bun workload-set fairness only
  - `benchmark reproduce` / `benchmark verify`: validates benchmark result bundles (`env.json`, `manifest.json`, `repro.lock`, `commands.txt`, `results.json`) and checks context consistency
  - recomputes publication-gate scores
  - compares claimed vs recomputed scores and publish decision
  - compares blocker sets
  - validates node/bun workload-set fairness
- Replay:
  - integrity + artifact-hash checks
  - replay fidelity checks
  - optional signature verification
  - optional receipt verification
  - optional counterfactual rechecks
- Containment:
  - scenario count consistency
  - passed-count and aggregate pass-flag consistency
  - per-scenario criteria consistency
  - latency-SLA checks
  - isolation and recovery invariant checks for passing scenarios
- Attestation:
  - canonical statement + report digest determinism
  - optional signature validation with embedded verifier key
  - embedded report linkage (claim type, context, verdict)

## CI Integration

Suggested gate pattern:

```bash
./scripts/run_third_party_verifier_suite.sh ci
franken-verify benchmark --input <bundle.json> --summary
franken-verify benchmark fairness --input <bundle.json> --summary
franken-verify benchmark reproduce --bundle <bundle_dir> --summary
franken-verify replay --input <bundle.json> --summary
franken-verify containment --input <bundle.json> --summary
```

Fail the pipeline on non-zero exit status.
