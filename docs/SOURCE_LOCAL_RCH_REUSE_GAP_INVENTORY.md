# Source-Local RCH Reuse Gap Inventory

This inventory supports `bd-jc2pl`. It records what the existing proof-economy
and RCH validation surfaces already prove, what they do not yet connect, and
the minimum data shape needed for a source-local lib-unit validation admission
composer.

## Baseline

`bd-0z9h9.4` closed on May 12, 2026 with this focused proof:

```bash
timeout 1800 rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_shadow_lock_validation RUSTFLAGS='-C linker=cc' cargo test -p frankenengine-engine --lib shadow_decision_composer::tests::output_dir_file_lock_blocks_second_writer_until_release -- --exact --nocapture
```

Observed result:

- `Finished test profile [unoptimized + debuginfo] target(s) in 22m 16s`
- `running 1 test`
- `shadow_decision_composer::tests::output_dir_file_lock_blocks_second_writer_until_release ... ok`
- `test result: ok. 1 passed; 0 failed; 40364 filtered out`
- no `frankenengine-test-support` compile line appeared in the Cargo output

That proves the support-heavy integration harness is no longer pulled into this
source-local lib-unit path. It also shows the remaining cost problem: rch used a
cold target for one exact test proof.

## Existing Surfaces

| Surface | Already captures | Missing for source-local reuse admission |
| --- | --- | --- |
| `scripts/rch_engine_lib_unit_smoke_gate.sh` | Package, target kind, exact test filter, direct `rch exec -- env` command, explicit `CARGO_TARGET_DIR`, `RUSTFLAGS`, `CARGO_INCREMENTAL`, `CARGO_BUILD_JOBS`, support-crate compile scan, local fallback scan, `commands.txt`, Cargo output log. | Stable source identity, Cargo.lock hash, toolchain identity, command fingerprint, worker identity, warm-target ownership, proof freshness, changed-path overlap, and reusable versus cold-refresh decision output. Its default target dir is timestamped, so it intentionally loses warm reuse. |
| `scripts/swarm_proof_command_preflight.sh` | Command normalization, heavy Cargo kind, direct rch transport, target-dir presence, target-dir correlation with bead id, env allowlist including `RUSTFLAGS` and `RUSTUP_TOOLCHAIN`, optional `RCH_VISIBILITY`, pasteable remediation, non-mutating artifacts. | It validates command shape only. It does not fingerprint package, target kind, exact test filter, Cargo.lock, covered source paths, support-crate contamination, proof freshness, or worker/target residency. |
| `scripts/proof_reuse_cache_planner.sh` | Proof index rows, source revision, artifact identity, artifact role, gate status, freshness reports, changed-path invalidation, reusable versus refresh versus invalid classification, refresh command metadata. | It depends on producers placing enough metadata in proof rows. It does not create a source-local lib-unit request identity or enforce Cargo.lock/toolchain/RUSTFLAGS/test-filter compatibility unless those values are already present in metadata. |
| `scripts/proof_reuse_admission_bundle.sh` | Composes proof-cache planner output with freshness, source revision/hash, command policy, target-dir policy, artifact role, changed-path overlap, anonymous artifact rejection, local fallback metadata, and advisory-only mutation policy. | It admits or rejects preserved proof artifacts, not a new live source-local validation request. It still needs a producer that normalizes the lib-unit request into metadata fields such as command fingerprint, Cargo.lock hash, toolchain, target kind, test filter, and support-contamination scan. |
| `scripts/sticky_worker_warm_target_lease_planner.sh` | Suite manifest phases, preferred worker, warm target dir, worker availability snapshot, reservation conflicts, local fallback marker snapshots, assigned worker/target plan, phase plans. | It is suite/worker oriented. It does not know whether a specific lib-unit proof request is source-compatible with a warm target, and it does not scan Cargo output for forbidden support dependencies. |
| `scripts/swarm_warm_target_prefetch_roi_advisory.sh` | Capacity forecast, admission budget, proof-cache plan, warm-target ROI ledger, archive pressure, replay trace cost, cache-hit/refresh counts, high-cost command counts, prefetch/reuse/cool/defer decisions. | It is an ROI advisory over upstream evidence. It does not emit an executable source-local rch validation command or validate exact package/test/toolchain/Cargo.lock compatibility. |
| `scripts/swarm_proof_cache_locality_optimizer.sh` | Admission, warm-target ROI, proof-cache, archive pressure, worker truth, resource envelope, topology placement, topology receipts, active locks, target pressure, worker schedulability, mutation-policy checks, reuse/fresh-target/cooling recommendations. | It needs many upstream artifacts and remains advisory. It does not provide the lightweight request adapter for a single source-local lib-unit proof. |
| `scripts/rch_validation_run_artifacts.sh` | Validation manifest, selected worker, remote command, safe rch-wrapped command, target-dir policy, required worker components, observed log markers, verdict, reason code, operator category, remediation, trace ids. | It classifies validation evidence after a case exists. It can wrap bare heavy Cargo into a generic target dir, but it does not preserve a source-local identity or decide safe warm reuse before scheduling. |
| `scripts/rch_policy_compliance_gate.sh` | Repository scan for bare heavy Cargo, missing `CARGO_TARGET_DIR` under rch, and local fallback text that is not rejected. | It is static policy compliance. It does not decide target reuse or validate proof metadata. |
| `scripts/rch_sync_closure_hotspot_ledger.sh` | Suite manifest commands, preserved transfer logs, sync closure roots, repeated full/narrow transfer hotspots, degraded status when transfer logs are missing. | It explains sync waste after preserved transfer evidence exists. It does not decide whether a warm target is safe for one lib-unit proof request. |

## Gap Summary

The missing object is a request-level admission record for source-local lib-unit
validation. Existing scripts can validate commands, preserved proof artifacts,
worker/target locality, and policy compliance, but no surface currently binds
these into one identity:

- source revision plus source hash
- Cargo.lock or dependency-root hash
- package name
- target kind (`lib`)
- exact test filter
- Cargo subcommand and arguments
- `RUSTFLAGS`
- `RUSTUP_TOOLCHAIN` or default toolchain identity
- env allowlist
- `CARGO_TARGET_DIR` policy
- worker identity and warm-target evidence when available
- changed-path coverage
- local fallback marker scan
- support-crate contamination scan

Without that record, the safest existing command shape uses a fresh timestamped
target dir, which avoids contamination but repeats cold remote builds.

## Proposed Input Contract For `bd-nvm2u`

The next bead should introduce or extend a producer that emits a compact request
record before scheduling a live rch proof:

```json
{
  "schema_version": "franken-engine.source-local-rch-validation-request.v1",
  "bead_id": "bd-nvm2u",
  "source_revision": "<git revision>",
  "source_hash": "<hash over request-covered source files>",
  "cargo_lock_hash": "<Cargo.lock hash>",
  "package": "frankenengine-engine",
  "target_kind": "lib",
  "test_filter": "shadow_decision_composer::tests::output_dir_file_lock_blocks_second_writer_until_release",
  "cargo_command": "cargo test -p frankenengine-engine --lib ... -- --exact --nocapture",
  "rustflags": "-C linker=cc",
  "toolchain": "<rustup toolchain or unknown>",
  "cargo_target_dir": "/tmp/rch_target_franken_engine_<stable-request-id>",
  "command_fingerprint": "<hash over command/env/source/dependency identity>",
  "worker_id": null,
  "changed_paths": [],
  "covered_paths": [
    "crates/franken-engine/src/shadow_decision_composer.rs"
  ],
  "required_scans": [
    "local_fallback",
    "frankenengine_test_support_compile"
  ]
}
```

The admission composer should then map this request into the existing surfaces:

1. run `swarm_proof_command_preflight.sh` on the normalized command;
2. query proof reuse/freshness artifacts when present;
3. ask sticky-worker or locality planners for worker/target suitability when
   their snapshots are available;
4. emit either a reusable/sticky rch command or a cold-refresh rch command;
5. fail closed on missing source/dependency identity, stale freshness, changed
   path overlap, local fallback markers, unsupported env, support-crate
   contamination, or worker/target ambiguity.

## Validation Scope

This inventory is source-only. No Cargo or rch validation was required for this
bead. The acceptance evidence is the existing `bd-0z9h9.4` closeout plus the
script inspection above.
