# External Trust Artifact UX Contract V1

`bd-grwh9.1` defines the V1 contract for external-trust artifact explainers:
deterministic, offline-first proof-reader surfaces that help an auditor,
downstream integrator, or security reviewer answer what supports a claim,
certificate, or evidence bundle and what is missing.

The contract is advisory and proof-reading only. It does not mutate Beads,
Agent Mail, reservations, worker state, claim wording, runtime policy, evidence
bundles, Git state, Cargo targets, or `rch` jobs. Later implementation beads may
add scripts or `frankenctl` commands that emit receipts from this contract, but
those commands must remain readers of existing artifacts, not new authorities.

Machine-readable companion:
[`external_trust_artifact_ux_contract_v1.json`](./external_trust_artifact_ux_contract_v1.json).

## Purpose

FrankenEngine already has evidence-bearing surfaces: the claim-to-proof matrix,
RGC gate bundles, benchmark and supremacy artifacts, E2 differential oracle
bundles, E3 flight-recorder outputs, and E8 data-contract / non-use certificate
artifacts. Those surfaces are authoritative for their own domains, but they are
not a unified auditor experience.

This contract defines the shared receipt shape for explainers that compose those
existing authorities. The explainer may say "supported", "degraded",
"not promotable", or "fail closed"; it must not invent a stronger claim than the
source artifacts support.

## Authority Sources

The explainer may read these source classes:

| Source class | Canonical source | Authority role |
| --- | --- | --- |
| Claim matrix JSON | `docs/claim_to_proof_matrix_v1.json` | Authoritative claim rows, allowed wording state, owning bead, artifact path, verification command, source span, downgrade text. |
| Claim matrix report | `docs/CLAIM_TO_PROOF_MATRIX_V1.md` | Human companion; not stronger than the JSON matrix. |
| Claim gate reports | `scripts/run_claim_to_proof_matrix_gate.sh ci` outputs | Gate verdicts, reason strings, failure taxonomy, downgrade text. |
| Proof artifact bundles | `artifacts/<gate>/<timestamp>/` | Bundle completeness, `run_manifest.json`, `events.jsonl`, `commands.txt`, trace ids, replay pointers. |
| RGC / benchmark / supremacy bundles | Existing RGC, performance, benchmark, parser, and supremacy gate outputs | Evidence payloads for release, performance, conformance, and claim support. |
| E2 differential bundles | Live Node/Bun/Franken differential oracle outputs | Cross-runtime denominator and divergence evidence. |
| E3 flight-recorder outputs | Existing recorder and explain artifacts when present | Runtime trace explanation and decision/event context. |
| E8 data-contract artifacts | `DataContract` and certificate bundle surfaces | Data ingress, purpose binding, declassification routes, non-use certificate context. |
| E8 refusal ledgers | `docs/e8_refusal_ledger_schema_v1.json` | Explicit E8 refusal evidence and runtime receipt schema. |
| Beads tracker | `.beads/issues.jsonl` and derived `br` DB state | Owning bead status and dependency context only; the explainer must not mutate it. |

The explainer must prefer the machine-readable source where both JSON and
Markdown exist. Markdown may supply operator context, but it is not an
independent authority for stronger proof claims.

## Non-Authority Boundary

The explainer is not:

- a claim promoter;
- a certificate prover;
- a replay runner;
- a Beads repair tool;
- an Agent Mail sender;
- a worker scheduler;
- a benchmark publisher;
- a rich TUI renderer;
- a substitute for E2, E3, E8, RGC, or claim-language gates.

Future rich interactive UI must be implemented through `/dp/frankentui`.
FrankenEngine may emit JSON and concise text reports that `/dp/frankentui` can
render, but this lane must not hard-code UI policy or implement a parallel
dashboard/control plane.

## Inputs

The V1 receipt model supports these input kinds:

| Input kind | Required fields | Notes |
| --- | --- | --- |
| `claim_matrix_row` | `claim_id`, `matrix_path`, `matrix_schema_version` | Used by the claim explainer. |
| `proof_artifact_bundle` | `bundle_path`, `declared_schema_version`, `bundle_family` | Used by the offline evidence bundle doctor. |
| `gate_report` | `gate_id`, `report_path`, `decision` | Links upstream validation output. |
| `bead_status_snapshot` | `bead_id`, `status`, `source` | Read-only tracker context. |
| `e2_differential_bundle` | `bundle_path`, `case_ids`, `runtime_arms` | Node/Bun/Franken divergence and denominator context. |
| `e3_flight_recorder_output` | `trace_path`, `decision_ids`, `event_count` | Trace explanation context when present. |
| `e8_certificate_bundle` | `contract_path`, `certificate_path`, `purpose_id` | Non-use certificate context; may be degraded until E8 certifier/capstone surfaces exist. |
| `e8_refusal_ledger` | `ledger_path`, `schema_version`, `result_class` | Explicit refusal input, not missing evidence. |

Every input record must preserve the source path and content hash when the bytes
are available. If bytes are not available, the receipt must say so explicitly
with a fail-closed or degraded reason.

## Receipt Output

Every explainer receipt must include:

| Field | Requirement |
| --- | --- |
| `schema_version` | Stable receipt schema, e.g. `franken-engine.external-trust-artifact-explanation.v1`. |
| `receipt_id` | Deterministic id derived from canonical receipt-core JSON. |
| `generated_at_utc` | Present but scrubbed in golden tests. |
| `decision` | One of `supported`, `degraded`, `not_promotable`, `fail_closed`, `unsupported`. |
| `reason_codes` | Stable reason-code array from this contract. |
| `source_inputs` | Input records with type, path, schema version, content hash, and freshness metadata. |
| `artifact_refs` | Artifact ids, paths, content hashes, required/optional flags, and missing status. |
| `claim_refs` | Claim ids, allowed wording state, actual wording state when known, source span, downgrade text, and owning bead. |
| `bead_refs` | Owning bead ids, status, assignee when known, blockers, and tracker source freshness. |
| `evidence_freshness` | Freshness days or declared unavailable reason. |
| `mock_status` | `absent`, `present_fail_closed`, or `unknown_fail_closed`. |
| `local_fallback_status` | `absent`, `present_fail_closed`, or `unknown_fail_closed` for heavy proof contamination. |
| `replay_commands` | Exact command strings when upstream artifacts declare them; no auto-execution. |
| `remediation` | Human-readable next action tied to a reason code. |
| `source_line_refs` | Source path and line span where available; absent spans must be explicit. |
| `mutation_policy` | All mutation flags false. |
| `renderer_boundary` | Future rich renderer provider `/dp/frankentui`; local renderer shipped `false`. |

Receipts must be deterministic after volatile fields are scrubbed. Golden tests
must scrub timestamps, absolute temp paths, hostnames, process ids, and worker
ids while preserving semantic ids, reason codes, content hashes, and source
paths.

## Decisions

| Decision | Meaning |
| --- | --- |
| `supported` | Required evidence is present, fresh enough for the upstream contract, not mock/local-fallback contaminated, and not contradicted by Beads or claim state. |
| `degraded` | The source is explainable, but the evidence is target/hypothesis, incomplete, stale, or waiting on an upstream lane. |
| `not_promotable` | The input can be read, but its claim/certificate/bundle must not be used to promote wording or trust state. |
| `fail_closed` | A required source is missing, invalid, contradictory, contaminated, or unsupported in a way that would make trust inference unsafe. |
| `unsupported` | The source family is outside the V1 allowlist; no trust conclusion is emitted, and CLI/gate wrappers must not exit as successful validation. |

`supported` is never allowed for a `target` or `hypothesis` claim unless the
receipt is explicitly explaining that weaker state and not promoting it.

## Fail-Closed Taxonomy

The V1 reason-code vocabulary is:

| Reason code | Trigger | Expected remediation |
| --- | --- | --- |
| `missing_claim_row` | Claim id absent from `claim_to_proof_matrix_v1.json`. | Add or correct the matrix row before explaining the claim. |
| `invalid_matrix_schema` | Matrix schema missing or unsupported. | Regenerate/fix the matrix and rerun the claim gate. |
| `unreadable_matrix` | Claim matrix path is missing, unreadable, or invalid JSON. | Read or regenerate the claim-to-proof matrix, then rerun the claim gate. |
| `missing_required_field` | A claim matrix row omits a field required for its wording state. | Fill the required matrix fields before explaining the claim. |
| `duplicate_claim_row` | More than one claim matrix row has the requested claim id. | Deduplicate the matrix row before explaining the claim. |
| `invalid_wording_state` | `allowed_state` or `actual_wording_state` is outside `hypothesis`, `target`, or `observed`. | Use the supported wording states before explaining the claim. |
| `wording_stronger_than_allowed` | Actual wording is stronger than the matrix allows. | Downgrade the wording or promote it only after upstream proof gates pass. |
| `claim_not_observed` | The matrix row is target/hypothesis, not observed proof. | Keep the explanation degraded/not-promotable until observed proof artifacts are linked. |
| `stale_tracker_state` | `.beads/issues.jsonl` and the derived DB disagree, or tracker freshness cannot be established. | Run the documented Beads sync/import/export path and re-read state. |
| `absent_artifact` | Required artifact path is missing. | Produce or attach the upstream gate bundle. |
| `missing_reproducibility_bundle` | Observed proof artifact is present but lacks a nearby `repro.lock`. | Add a reproducibility bundle before treating the claim as supported. |
| `invalid_expected_hash` | Matrix expected hash is not `sha256:<64-hex>` or bare 64-hex. | Replace the expected artifact hash or omit it until an authority source exists. |
| `artifact_hash_mismatch` | Matrix expected hash does not match the artifact bytes. | Regenerate the artifact from the recorded replay command or correct the matrix hash authority. |
| `stale_artifact` | Claim-level freshness budget or observed artifact freshness is stale/unknown. | Refresh the observed proof artifact or downgrade the claim before treating it as supported. |
| `incomplete_artifact_bundle` | Required bundle member such as `run_manifest.json`, `events.jsonl`, or `commands.txt` is absent. | Re-run the upstream gate or point at a complete preserved bundle. |
| `malformed_manifest` | Bundle manifest JSON/TOML cannot be parsed as an object. | Fix the manifest syntax/schema before using the bundle as evidence. |
| `invalid_required_member` | Bundle manifest `required_members` is empty, contains entries without non-empty string paths, declares malformed or conflicting member hashes, or uses non-boolean `required` flags. | Fix the manifest so required members are explicit root-relative paths or path objects with boolean `required` flags and valid, non-conflicting SHA-256 hex hash fields. |
| `path_escape` | A bundle manifest member path resolves outside the declared bundle root. | Reject the bundle and regenerate it with root-relative member paths only. |
| `unsupported_schema` | Bundle schema/version outside V1 allowlist. | Add schema support in a future bead or use a supported bundle. |
| `hash_mismatch` | Declared hash does not match available bytes. | Treat artifact as untrusted and regenerate from source. |
| `mock_contaminated` | `MockCertificate`, `hot_paths_simulation`, placeholder, or fixture-only evidence is used for an observed proof claim. | Replace with a live/preserved non-mock proof artifact. |
| `local_fallback_contaminated` | Heavy proof command used local Cargo or non-remote fallback where the contract requires `rch`. | Re-run through `rch` and attach the remote proof bundle. |
| `contradictory_bead_status` | Matrix or receipt says observed/done while owning bead is blocked/open without an explicit exception. | Resolve tracker status or downgrade the claim. |
| `missing_replay_command` | Upstream artifact claims replayability but has no exact replay command. | Regenerate bundle with command transcript/replay metadata. |
| `invalid_replay_command` | Bundle manifest declares replay command fields with non-string or empty string values. | Fix the manifest so every declared replay command is an exact non-empty command string. |
| `stale_or_unfresh` | Freshness exceeds upstream maximum, cannot be computed, or any declared freshness alias is stale/malformed. | Regenerate evidence or emit degraded state. |
| `unavailable_e8_certifier` | E8 certificate/capstone artifact is not yet available. | Emit degraded/non-promotable E8 report until certifier surfaces land. |
| `explicit_e8_uncertified_refusal` | Non-certifiable ledger or refusal codes. | Preserve details; block positive wording. |
| `malformed_e8_refusal_ledger` | Invalid schema, code, class, or source ref. | Treat as untrusted; rerun the E8 producer. |
| `duplicate_e8_identifier` | E8 route, binding, claim, purpose, or data-source id repeats where uniqueness is required. | Fix the data contract/certifier input and rerun upstream validation. |
| `unknown_e8_claim_reference` | E8 certificate references a claim id absent from the matrix. | Add/correct matrix linkage or reject the certificate report. |
| `invalid_source_span` | Matrix source span has invalid one-based line numbers. | Use one-based source span line numbers with `start_line <= end_line`. |
| `source_path_missing` | Matrix source path cannot be located. | Restore the source path or update the matrix before treating the claim as supported. |
| `source_path_unreadable` | Matrix source path exists but cannot be read. | Make the source readable or update the matrix before explaining the claim. |
| `source_span_mismatch` | Matrix `must_contain` text is absent from the declared source span. | Update the source span or downgrade the claim until source text matches. |
| `source_span_unavailable` | Source line references cannot be located. | Preserve path-only source ref and mark line span unavailable. |
| `unsupported_input_kind` | Input family is outside the V1 contract. | Add an explicit future contract extension before trusting it. |

If multiple reason codes apply, receipts must include all of them and choose the
most conservative decision in this order:

`fail_closed` > `unsupported` > `not_promotable` > `degraded` > `supported`.

CLI and smoke/gate wrappers may exit zero only for `supported` or explicitly
`degraded` receipts. `unsupported`, `not_promotable`, and `fail_closed`
receipts are readable outputs, but they are non-success validation outcomes.

## Overlap Map

This lane deliberately composes existing surfaces instead of replacing them.

| Existing lane | What it owns | What this contract adds |
| --- | --- | --- |
| SWARM-OPS-P0 | Operational status, dashboards, swarm runbooks. | External artifact explanation receipts only; no queue/dashboard ownership. |
| SWARM-CTRL | Control-plane advisory and validation workflow. | Trust-artifact reader boundary; no control-plane mutation or scheduling. |
| SWARM-AUTOPILOT | Autopilot hindsight, warehouse, panels, policy bundles. | Reads autopilot-style artifacts only if supplied; does not tune queues. |
| Actionability truth gates | Whether a bead is safe to claim or defer. | Explains owning bead status as evidence context, not a claimability oracle. |
| Agent Mail identity repair | Mail identity reconciliation and SLA panels. | No Agent Mail mutation; may cite archived messages only if supplied as artifacts. |
| Proof-cache locality | Cache freshness, reuse/admission, remote proof economics. | Reports freshness/local-fallback status; does not warm or evict caches. |
| RCH stall ledgers | Remote worker stall/no-verdict diagnostics. | Flags local fallback or missing remote proof; does not run/cancel `rch`. |
| Claim-to-proof matrix gate | Source-of-truth claim wording and allowed state. | Human/auditor explanation over matrix rows; cannot override the gate. |
| E2/E3/E8 tracks | Produce differential, recorder, and certificate evidence. | Reads their artifacts and explains missing/degraded states; cannot prove them. |
| E8 refusal-ledger track | Refusal vocabulary and fixtures. | Preserves refusal; cannot certify. |

## Test Obligations For Child Beads

Later implementation beads must include fixture-friendly tests for:

- observed claim explanation with stable hashes and owning bead refs;
- target/hypothesis claim explained as degraded or not promotable;
- missing claim row;
- stale or contradictory tracker state;
- complete proof artifact bundle;
- missing bundle member;
- malformed bundle manifest;
- malformed or non-string bundle freshness;
- invalid required-member declaration;
- bundle member path escape;
- unsupported schema;
- hash mismatch;
- mock-contaminated certificate or simulated hot-path artifact;
- local-fallback heavy proof contamination;
- missing replay command;
- invalid replay command shape;
- E8 duplicate id;
- E8 missing certifier/capstone evidence;
- E8 explicit uncertified refusal ledger;
- E8 malformed refusal ledger or missing refusal source ref;
- E8 positive non-use wording blocked by refusal evidence;
- E8 unknown claim reference.

Golden tests must keep semantic ids, reason codes, and content hashes intact.
No-mock auditor drills must use checked-in or preserved artifacts and must not
contact live services unless a later contract explicitly adds a live mode.

## Consumer Contract

Supported consumers:

- shell scripts that validate contract shape and emit fixture receipts;
- `frankenctl` report/doctor/explain commands added by later beads;
- `/dp/frankentui` renderers that consume emitted JSON without owning proof
  semantics;
- downstream `/dp/franken_node` staging workflows that need auditor-facing
  trust explanations.

All consumers must preserve the same decision vocabulary, reason codes,
mutation policy, and renderer boundary. Any consumer that wants to promote a
claim, prove certificate soundness, or run a replay must call the owning
upstream gate instead of treating this explainer as authority.
