# External Trust Artifact UX Runbook

Operator, auditor, and downstream staging runbook for FrankenEngine's external-trust proof-reader surfaces (`bd-grwh9`).

Normative contract and reason-code taxonomy:
- [`docs/EXTERNAL_TRUST_ARTIFACT_UX_CONTRACT_V1.md`](../docs/EXTERNAL_TRUST_ARTIFACT_UX_CONTRACT_V1.md)
- [`docs/external_trust_artifact_ux_contract_v1.json`](../docs/external_trust_artifact_ux_contract_v1.json)

## Advisory Proof-Reader Boundary (Non-Authority Disclosure)

Every command in this runbook is a deterministic, offline-first **advisory proof-reader**. None of these commands is an authority source on its own:

- The explainer does **not** establish runtime soundness; upstream runtime/IFC/guardplane gates own runtime verification.
- The explainer does **not** certify E8 non-use or non-exfiltration soundness; only the upstream E8 certifier and capstone bundle (`scripts/run_dw_non_use_certificate.sh`) produce certificates, while `scripts/e8_non_use_certificate_scenario_report.py` inspects them.
- The explainer does **not** execute or verify replay runs; it surfaces recorded `replay_commands` from upstream manifests or `repro.lock` files without running Cargo or `rch`.
- Freshness reporting reads upstream receipt fields (`artifact.actual_freshness_days`, `artifact.freshness_status`, `evidence_freshness`) against the matrix window (`docs/claim_to_proof_matrix_v1.json`) and upstream gate outputs (`scripts/run_claim_to_proof_matrix_gate.sh ci`); reading an old bundle does not refresh it.
- No claim is promotable from transport-only evidence (such as `rch` dispatch logs or partial transfer receipts without an upstream gate verdict).
- Mutation flags in `mutation_policy` stay `false`: these readers do not modify `.beads/issues.jsonl`, Agent Mail, worker reservations, claim wording, Git state, or evidence bundles.

## 1. Explain a Claim Row (`frankenctl claims explain`)

Inspect whether a specific `FE-CLAIM-*` row in `docs/claim_to_proof_matrix_v1.json` is currently `supported`, `not_promotable`, `degraded`, or `fail_closed`:

```bash
./target/release/frankenctl claims explain FE-CLAIM-006 \
  --matrix docs/claim_to_proof_matrix_v1.json \
  --beads-jsonl .beads/issues.jsonl \
  --format json \
  --out /tmp/claim_explain_fe_claim_006.json
```

Expected receipt schema: `franken-engine.external-trust-claim-explainer.v1`.
Key fields to inspect before staging:
- `decision`: `supported` (exit `0`), `degraded` (exit `0`), `not_promotable` (exit `1`), `fail_closed` (exit `2`), or `unsupported` (exit `2`).
- `reason_codes`: e.g. `claim_not_observed` for `target`/`hypothesis` rows, `stale_artifact` when `artifact.actual_freshness_days` exceeds `max_observed_freshness_days`, `contradictory_bead_status` when an `observed` row points at an open bead.
- `artifact`: `content_hash`, `actual_freshness_days`, `freshness_status`, `max_observed_freshness_days`.
- `replay_commands` and `remediation`: exact upstream gate command required to regenerate or verify evidence.

## 2. Doctor an Offline Proof Bundle (`external_trust_artifact_bundle_doctor.py`)

Verify completeness, SHA-256 member digests, replay command presence, and absence of mock (`MockCertificate`, `hot_paths_simulation`) or local-fallback markers on a preserved bundle:

```bash
python3 scripts/external_trust_artifact_bundle_doctor.py \
  --bundle scripts/testdata/e8_non_use_certificate_scenario_report/certified_bundle \
  --pretty > /tmp/bundle_doctor_receipt.json
```

Expected receipt schema: `franken-engine.external-trust-artifact-bundle-doctor.v1`.
- Exits `0` only for `supported` or `degraded`; exits `1` for `fail_closed`, `not_promotable`, or `unsupported`.
- Uncertified or contradicted E8 refusal bundles emit `decision: "not_promotable"` with `explicit_e8_uncertified_refusal`.

## 3. Inspect an E8 Non-Use Certificate Scenario (`e8_non_use_certificate_scenario_report.py`)

Render either a deterministic JSON receipt or a concise human security-review report comparing an E8 `DataContract` against its emitted certificate bundle:

```bash
# Machine-readable JSON receipt
python3 scripts/e8_non_use_certificate_scenario_report.py \
  --contract scripts/testdata/e8_non_use_certificate_scenario_report/contract_honest.json \
  --bundle scripts/testdata/e8_non_use_certificate_scenario_report/certified_bundle \
  --beads-jsonl .beads/issues.jsonl \
  --format json --pretty > /tmp/e8_scenario_receipt.json

# Concise human text report for security review
python3 scripts/e8_non_use_certificate_scenario_report.py \
  --contract scripts/testdata/e8_non_use_certificate_scenario_report/contract_honest.json \
  --bundle scripts/testdata/e8_non_use_certificate_scenario_report/certified_bundle \
  --beads-jsonl .beads/issues.jsonl \
  --format text
```

Expected receipt schema: `franken-engine.external-trust-artifact-explanation.v1`.
- Missing capstone/certifier files emit `unavailable_e8_certifier` (`fail_closed`).
- Contradicted smuggle runs emit `not_promotable` (`explicit_e8_uncertified_refusal`), blocking positive non-exfiltration wording.

## 4. Run the No-Mock Auditor Drill and Paired Truth Gate

Compose all three proof-readers across 12 positive and negative scenarios without mutating repository state:

```bash
# Deterministic fixture/replay mode (expects overall_decision == "pass")
python3 scripts/external_trust_no_mock_auditor_drill.py \
  --mode fixture \
  --frankenctl-bin target/release/frankenctl \
  --out-dir /tmp/external_trust_drill_fixture

python3 scripts/check_external_trust_auditor_drill_truth_gate.py \
  --drill-dir /tmp/external_trust_drill_fixture

# Live repository mode (surfaces stale observed bundles truthfully as "degraded")
python3 scripts/external_trust_no_mock_auditor_drill.py \
  --mode live \
  --frankenctl-bin target/release/frankenctl \
  --out-dir /tmp/external_trust_drill_live

python3 scripts/check_external_trust_auditor_drill_truth_gate.py \
  --drill-dir /tmp/external_trust_drill_live
```

Emitted drill artifacts in `--out-dir`:
- `run_manifest.json` (`franken-engine.external-trust-auditor-drill.v1`)
- `stages/01_claim_observed.json` .. `stages/12_replay_command_absent_fail_closed.json`
- `commands.txt`, `reason_code_summary.json`, `artifact_hashes.json`, `remediation.txt`

## 5. Validation Transport Blocker States (First-Class Triage)

Auditors and operators must distinguish upstream source failures from validation transport blockers. Transport logs alone never support claim promotion:

| Blocker State | First Blocker Signal | Resulting Receipt Posture | Required Next Condition |
| --- | --- | --- | --- |
| `source_or_test_failure` | Upstream compiler, test, or gate script exits non-zero with diagnostic error. | `fail_closed` (`absent_artifact` or failed gate report) | Fix source/test defect and re-run the owning upstream gate via `rch`. |
| `rch_admission_denial` | `rch` rejects remote admission, worker probe fails, or local fallback is refused (`local_fallback_refused`). | Refusal is **not** mock contamination (`bd-grwh9.28`), but claim stays `fail_closed` / `degraded` until remote verdict exists. | Probe a healthy `rch` worker with `/data` `CARGO_TARGET_DIR` and produce a remote verdict; never substitute local Cargo for heavy proof. |
| `remote_stale_or_no_verdict` | Remote worker stalled, timed out (`RCH-E330`), or left no receipt/`repro.lock`. | `fail_closed` (`absent_artifact` / `missing_reproducibility_bundle` / `stale_artifact`) | Re-run with bounded build jobs and collect complete `run_manifest.json` + `repro.lock`. |
| `partial_artifact_bundle` | Bundle directory exists, but required member (`events.jsonl`, `commands.txt`, `repro.lock`) is absent or truncated. | `fail_closed` (`missing_required_member` / `incomplete_artifact_bundle` / `hash_mismatch`) | Regenerate the complete bundle from the recorded upstream replay command. |
| `explicit_owner_signoff_or_target_posture` | Row has `allowed_state` in `target`/`hypothesis`, unratified ADR, or explicit E8 refusal ledger. | `not_promotable` (`claim_not_observed` / `explicit_e8_uncertified_refusal`) | Land the upstream capability + live proof gate (and owner ratification where required) before promoting wording. |

## 6. Attaching Receipts to Release or `/dp/franken_node` Staging Decisions

1. Run `frankenctl claims explain`, `external_trust_artifact_bundle_doctor.py`, and (when E8 data contracts apply) `e8_non_use_certificate_scenario_report.py`, archiving their JSON receipts alongside the staging manifest.
2. Require `decision == "supported"` and paired truth-gate `verdict == "pass"` before promoting any release note or `/dp/franken_node` capability badge.
3. Run the documentation claim-language truth gate (`python3 scripts/check_external_trust_docs_truth_gate.py`) whenever editing trust-artifact docs or `README.md`.
