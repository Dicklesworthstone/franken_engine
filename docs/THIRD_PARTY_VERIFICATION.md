# Third-Party Reproducibility Verification — External Auditor Guide

> Track N (`bd-cixqu.14`). Operator surface: `bd-cixqu.14.4` (N.4).
> Producer: N.1 per-claim triple emission under [`docs/evidence/`](./evidence/).
> Single-source-of-truth checker: N.2 [`scripts/third_party_repro_lock_verifier.sh`](../scripts/third_party_repro_lock_verifier.sh).
> Operator wrapper: [`runbooks/scripts/run_third_party_verifier.sh`](../runbooks/scripts/run_third_party_verifier.sh).
> Drift diagnostician: [`runbooks/scripts/diagnose_env_drift.sh`](../runbooks/scripts/diagnose_env_drift.sh).

This document is for **external auditors** (and operators) who receive a
FrankenEngine release artifact and want to **independently verify that it
reproduces** — without trusting, or even reading, the FrankenEngine engine
source. Reproducibility is only a real property if a stranger can confirm it; if
verifying is hard, nobody runs it and the claim becomes paper-only. So the whole
procedure is a single command over an artifact you already hold.

It complements [`docs/PROOF_BUNDLE_VERIFICATION.md`](./PROOF_BUNDLE_VERIFICATION.md)
(Track Y): that guide re-checks *formal proofs*; this guide re-checks
*deterministic reproduction* of a claim's evidence.

---

## What you are verifying

Every published claim ships a **reproducibility triple** under
`docs/evidence/<FE-CLAIM-NNN>/`:

| File | Schema | What it is |
|---|---|---|
| `repro.lock` | `frankenengine.reproducibility.lock.v1` | The deterministic replay recipe: the exact command sequence, a fail-closed determinism policy, the source commit, and the locked input hashes. This is the trust artifact. |
| `env.json` | `frankenengine.reproducibility.env.v1` | The *recorded* environment the artifact was produced in: host (CPU/kernel/OS), toolchain (cargo/rustc/target), and the project commit. |
| `manifest.json` | per-claim | The evidence manifest binding the bundle together. |

The `repro.lock` is the contract: it says "run *these* commands in *this*
deterministic environment and you will reproduce the claim's evidence." The
verifier's job is to confirm that contract is (a) well-formed and fail-closed,
and (b) actually reproduces — independently of the engine source.

---

## What you need

- `bash`, `jq`, `python3` (a laptop is enough).
- The published claim-evidence bundle (a `docs/evidence/<CLAIM>/` directory, or
  just its `repro.lock`).
- For `--execute` (actually re-running the locked build commands): the Rust
  toolchain, and `rch` if the locked commands route through it. Not required for
  the default plan-only validation.

You do **not** need to understand the gate script that produced the artifact, or
have the engine source tree, to validate the lock and derive its replay plan.

---

## Verify in one command

```bash
# Validate the bundle's repro.lock + diagnose whether this host drifts from the
# environment the artifact was recorded in. Writes a typed verdict + run bundle.
runbooks/scripts/run_third_party_verifier.sh verify docs/evidence/FE-CLAIM-001
```

```bash
# Strongest isolation: run the same checker inside a pinned clean-room image you
# trust (bash + jq). Plan-only; no engine source on the host is consulted.
runbooks/scripts/run_third_party_verifier.sh verify docs/evidence/FE-CLAIM-001 \
  --via docker --image <your-pinned-image>

# Actually re-run the locked commands end-to-end (needs the Rust toolchain).
runbooks/scripts/run_third_party_verifier.sh verify docs/evidence/FE-CLAIM-001 --execute
```

The verifier never re-implements anything engine-specific. It is a thin,
auditable orchestrator over the N.2 checker
([`scripts/third_party_repro_lock_verifier.sh`](../scripts/third_party_repro_lock_verifier.sh)),
which simply extracts the locked command sequence, enforces the determinism
policy, and (with `--execute`) replays it.

### Expected output (a faithfully-recorded bundle)

```json
{
  "classification": "verified",
  "verifier_verdict": "planned",
  "bundle_complete": true,
  "command_count": 1,
  "env_drift": { "diagnosed": true, "verdict": "aligned" },
  "next_action": "The deterministic replay plan validated ... environment is aligned."
}
```

---

## The four outcomes (and exactly what to do)

| Classification | Exit | Meaning | What to do |
|---|---|---|---|
| `verified` | 0 | The lock validated (plan-only) or replayed to its expected outcome (`--execute`); environment aligned. | Rely on it. To go further, re-run with `--execute` on a matching host. |
| `env_drift` | 0 (advisory; `2` under `--strict-drift`) | The lock still validates, but the host you are replaying on differs from the recorded `env.json`. | Reproduce on a matching environment before drawing a conclusion (see *Reading env drift* below), or accept the advisory if the drift is immaterial to the claim. |
| `verification_failed` | 1 | The checker rejected the lock (not a repro.lock schema, determinism policy not fail-closed, no replay command) or a replayed command failed. | The artifact is **not** verified. Escalate to the FrankenEngine maintainers. |
| `bundle_incomplete` | 1 | The N.1 triple is missing `env.json`, `manifest.json`, or `repro.lock`. | Request a re-exported bundle; an incomplete triple cannot be a trust artifact. |

(Exit `3` is a CLI/environment error — target not found, `--via docker` without
an `--image`, missing `jq`/`python3`.)

### Why the env_drift / verification_failed split matters

The two questions an auditor must keep separate are *"did the inputs/environment
change?"* and *"did the artifact regress?"*. A reproduction that diverges because
you ran it on a different CPU or a newer Rust is **not** evidence of a regression
— it is evidence you changed the experiment. Conflating the two produces both
false alarms (blaming the artifact for a toolchain bump) and false confidence
(missing a real regression behind environment noise).

Because the lock check (does the recipe validate/replay?) and the env diagnosis
(does this host match the recorded one?) are computed independently, the verdict
separates them cleanly: `verification_failed` implicates the **artifact**;
`env_drift` implicates the **environment**.

---

## Pinning a repro.lock from a published artifact

Pin the lock you verified by its content hash, so a later re-verify proves you
re-checked the same bytes the release published:

```bash
sha256sum docs/evidence/FE-CLAIM-001/repro.lock

# The lock's own provenance — schema, source commit, locked command sequence.
jq '{schema_version, source_commit, replay, determinism}' \
  docs/evidence/FE-CLAIM-001/repro.lock
```

The operator verdict echoes `lock_schema_version` and `source_commit`, and the
run bundle (`artifacts/third_party_verifier_operator/<ts>/`) records the lock
hash in `run_manifest.json`, so your pin is captured for the audit trail.

---

## Reading env drift (recorded vs replayed)

When the verdict is `env_drift`, get the field-level breakdown:

```bash
runbooks/scripts/diagnose_env_drift.sh diagnose \
  --recorded docs/evidence/FE-CLAIM-001/env.json \
  --lock docs/evidence/FE-CLAIM-001/repro.lock
```

```bash
# Or compare two recorded snapshots directly (e.g. two published releases).
runbooks/scripts/diagnose_env_drift.sh diagnose \
  --recorded release-a/env.json --current release-b/env.json
```

Every difference is classified into exactly one of three operator-actionable
buckets:

| Drift class | Fields | What a divergent replay means |
|---|---|---|
| **platform drift** | `host.architecture` (CPU), `host.kernel`, `host.os_version`, `host.platform` | You replayed on a different machine class. Platform-sensitive outputs may legitimately differ — reproduce on a matching platform. |
| **toolchain drift** | `toolchain.cargo_version`, `toolchain.rust_version`, `toolchain.rustc_target` | The Rust toolchain differs. Pin the recorded toolchain before concluding the artifact regressed. |
| **dependency drift** | `project.commit`; with `--lock`, the locked `inputs.primary_artifact.hash` and the presence of every declared dependency file | The *inputs* differ. A divergent replay is expected, not a regression. |

The diagnosis verdict (`franken-engine.env-drift-diagnosis.v1`) reports a
per-class count and the exact `recorded` → `current` value for each field. Only
when all three counts are zero (`verdict: aligned`) does a divergent verify
implicate the **artifact** itself.

```json
{
  "verdict": "drift",
  "drift_class_count": { "platform": 2, "toolchain": 2, "dependency": 1 },
  "drifts": [
    { "class": "platform", "field": "host.kernel",
      "recorded": "6.17.0-22-generic", "current": "6.17.0-35-generic" }
  ]
}
```

---

## Manual verification (no wrapper)

The wrapper adds classification + drift diagnosis + a logged run bundle, but the
core check is just the N.2 checker, which you can run directly:

```bash
# Validate the lock and derive its deterministic replay plan (no execution).
scripts/third_party_repro_lock_verifier.sh \
  --lock docs/evidence/FE-CLAIM-001/repro.lock --plan-only --report report.json

# Inspect the derived plan and the fail-closed determinism verdict.
jq '{verdict, deterministic_policy_ok, command_count, commands}' report.json
```

The report schema is `franken-engine.third-party-repro-lock-verifier-report.v1`.
The verifier toolkit reference is
[`docs/THIRD_PARTY_VERIFIER_TOOLKIT.md`](./THIRD_PARTY_VERIFIER_TOOLKIT.md).

---

## How this fits the release

The N.3 universality gate
([`scripts/run_rgc_reproducibility_universality.sh`](../scripts/run_rgc_reproducibility_universality.sh))
proves that *every* claim's `repro.lock` in the corpus is verifier-consumable, so
the property is universal rather than demonstrated on one hand-picked claim. The
GA-exit evidence package (`bd-cixqu.47`) requires that universality gate green.
This N.4 surface is the per-bundle tool an auditor uses against the published
release once it ships.

Scope (intentional): the perf/denominator-lineage locks
(`franken-engine.repro-lock.v1` in `docs/perf/e2_denominator_bundle_v1` and
`benchmarks/runtime_comparison`) lock the byte-identical correctness-verdict hash
while allowing wall-clock timing to vary, which the strict third-party verifier
deliberately rejects. They are verified by
[`scripts/run_e2_denominator_bundle_gate.sh`](../scripts/run_e2_denominator_bundle_gate.sh)
and are out of scope for this strict-deterministic verifier.

---

## Reference

| Surface | Path |
|---|---|
| Operator wrapper | [`runbooks/scripts/run_third_party_verifier.sh`](../runbooks/scripts/run_third_party_verifier.sh) |
| Drift diagnostician | [`runbooks/scripts/diagnose_env_drift.sh`](../runbooks/scripts/diagnose_env_drift.sh) |
| N.2 checker (single source of truth) | [`scripts/third_party_repro_lock_verifier.sh`](../scripts/third_party_repro_lock_verifier.sh) |
| N.3 universality gate | [`scripts/run_rgc_reproducibility_universality.sh`](../scripts/run_rgc_reproducibility_universality.sh) |
| Verifier toolkit reference | [`docs/THIRD_PARTY_VERIFIER_TOOLKIT.md`](./THIRD_PARTY_VERIFIER_TOOLKIT.md) |
| Operator-gates section | [`docs/operator-gates/RGC_GATES_REFERENCE.md`](./operator-gates/RGC_GATES_REFERENCE.md) → *Reproducibility verifier (third-party)* |
| Reproducibility contract | [`docs/REPRODUCIBILITY_CONTRACT.md`](./REPRODUCIBILITY_CONTRACT.md) |
