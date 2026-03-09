# RGC Observability Channel Policy V1

Status: active
Primary bead: bd-1lsy.11.20.1
Track id: RGC-066A
Machine-readable contract: `docs/rgc_observability_channel_policy_v1.json`

## Purpose

`RGC-066A` makes approximate engine telemetry explicit, deterministic, and
auditable. The contract exists to prevent hidden downsampling or sketching from
leaking into replay, security, legal-provenance, or support-bundle surfaces.

The policy distinguishes:

- lossless evidence families that must remain exact
- approximate families that may use deterministic sampling and bounded sketches
- operator-visible modes that change capture semantics
- site-level rules that bind components to allowed modes and sketch families
- replay fixtures that prove sampling decisions are reproducible

## Channel Policy

The engine-level policy classifies evidence families into two groups:

- lossless-only: `replay`, `security`, `legal_provenance`
- approximate-allowed: `decision`, `optimization`

Redaction is mandatory before sampling, and every emitted artifact must expose
the capture mode, sampling seed, and telemetry site identifier. No contract may
silently route support-bundle export, replay validation, or legal provenance
through a lossy path.

## Operator Modes

The operator mode contract defines precedence and semantics for:

- `default_capture`
- `degraded`
- `exact_shadow`
- `support_bundle_export`
- `incident_full_capture`

Higher-precedence modes override lower-precedence modes when a site explicitly
allows them. `incident_full_capture` and `support_bundle_export` are always
lossless. `degraded` is only valid for approximate families and still requires
current calibration evidence.

## Telemetry Site Policy Matrix

The site matrix binds concrete engine telemetry sites to evidence families,
allowed modes, sketch families, distortion budgets, and redaction rules.

Required covered sites include:

- `runtime_observability.auth_failure_total`
- `runtime_observability.capability_denial_total`
- `runtime_observability.replay_drop_total`
- `observability_channel_model.decision_lattice`
- `entropy_evidence_compressor.optimization_entropy`
- `observability_channel_model.legal_archive`

Lossless sites carry zero distortion budgets and empty sketch-family sets.

## Sampling And Sketch Contracts

The sampling contract defines deterministic seed material, strategy, stride or
weighted-skip configuration, precision targets, and replay-stability rules per
site. Approximate sites use one of:

- `count_min`
- `hyper_log_log`
- `kll`
- `heavy_hitter`
- `nitro_sketch_weighted`

The sketch error envelope report publishes explicit bias, variance, collision,
and quantile-error bounds plus the minimum exact-shadow sample count required to
keep the sketch publishable.

## Replay Fixture Matrix

`sampling_seed_replay_fixture_matrix.json` proves that deterministic sampling is
derived from canonical inputs:

- `trace_id`
- `workload_id`
- `manifest_hash`
- `site_id`
- `mode`

Each fixture includes the expected seed hash and expected interval so the
capture schedule is reproducible across machines and reruns.

## Structured Logging And Artifact Contract

Validation and replay runs must emit structured logs with these required fields:

- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `outcome`
- `error_code`
- `observability_mode`
- `sampling_seed`
- `site_id`

Artifacts are emitted under:

`artifacts/rgc_observability_channel_policy/<UTC_TIMESTAMP>/`

with:

- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `engine_observability_channel_policy.json`
- `operator_mode_contract.json`
- `telemetry_site_policy_matrix.json`
- `telemetry_sampling_contract.json`
- `sketch_error_envelope_report.json`
- `sampling_seed_replay_fixture_matrix.json`

## Operator Verification

```bash
jq empty docs/rgc_observability_channel_policy_v1.json

./scripts/run_rgc_observability_channel_policy.sh ci

./scripts/e2e/rgc_observability_channel_policy_replay.sh ci
```
